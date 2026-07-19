//! Snapshot pending bridge withdrawals, obtain their Wormhole VAA, construct
//! the authorized Dogecoin transaction off-chain, obtain Manager signatures,
//! and optionally broadcast it.
//!
//! Snapshotting is the sole batching and authorization boundary.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use bitcoin::{hashes::Hash as BitcoinHash, BlockHash};
use clap::Parser;
use doge_bridge_client::{
    instructions,
    operator_store::{
        CustodyReservation, CustodyReservationStatus, CustodyUtxo, CustodyUtxoStatus,
        DogecoinTransaction, OperatorStatus, OperatorStore, ProcessWithdrawal, SnapshotBatch,
        WithdrawalRequest,
    },
    BridgeHistorySync, HistoryRecord, HistorySyncConfig, NoopShimMonitor, NoopShimMonitorConfig,
    WithdrawalRequestRecord,
};
use psy_doge_solana_core::{
    constants::DOGECOIN_CHAIN_ID,
    instructions::doge_bridge::SnapshotWithdrawalsInstructionData,
    program_state::PsyWithdrawalRequest,
    snapshot_withdrawal_proof::{SnapshotWithdrawalProof, SNAPSHOT_PROOF_MAX_BATCH},
};
use reqwest::Client as HttpClient;
use ripemd::Ripemd160;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signature, Signer},
    system_instruction,
    transaction::Transaction,
};
use solana_transaction_status::UiTransactionEncoding;
use tokio::time::sleep;

use crate::wormhole::{
    manager::{
        fetch_manager_signatures, fetch_signed_vaa, manager_set_for_index, parse_vaa,
        vaa_hash_matches, verify_manager_signature, ManagerSet, ManagerSignatures,
    },
    redeem::build_redeem_script,
    tx::{double_sha256, p2sh_script_pubkey, SelectedUtxo, TransactionOutput, UnsignedTransaction},
    utx0::{Utx0Output, Utx0UnlockPayload, UtxoAddressType},
};
use crate::{custody_ops, plan_custody_transaction, CustodyTransactionPlan};
use crate::network::{fill_string, fill_string_optional, fill_u32, DogeNetwork, RuntimeNetwork};

const DEFAULT_DOGE_BRIDGE: &str = "9HdfoY6yYFLo3sQ5qMv9tHHgXzB3AnA2GXXyedeWrLdN";
const DEFAULT_PENDING_MINT: &str = "DHB58D8HbnRM7QQiJ37iE3YjCfUbzbhpcc2Bf5rAXkua";
const DEFAULT_TXO_BUFFER: &str = "9N217cCfEhickevyD3amY1BQh8P8Hay7CKKWa5kgrgHs";
const DEFAULT_GENERIC_BUFFER: &str = "marxYjRRhMAmfyGPNwkKEgwzKsSNfmKQ4gzMLadZxuz";
const DELEGATED_MANAGER_SET_PROGRAM_ID: &str = "wdmsTJP6YnsfeQjPuuEzGCrHmZvTmNy8VkxMCK8JkBX";
const GENERIC_BUFFER_HEADER_SIZE: usize = 32;
const GENERIC_BUFFER_CHUNK_SIZE: usize = 878;
const SNAPSHOT_COMPUTE_UNITS: u32 = 1_400_000;
const WORMHOLE_FEE_PREPAY_LAMPORTS: u64 = 1_000;
const DUST_THRESHOLD_SATS: u64 = 10_000;
const SOLANA_EMITTER_CHAIN: u16 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "withdraw",
    about = "Snapshot, sign, and broadcast pending Dogecoin withdrawals",
    long_about = "Resumes any incomplete persisted snapshot first; otherwise snapshots up to 319 withdrawal requests, proves the batch against the requested-withdrawals Merkle tree, posts the exact outputs-only UTX0 payload via Wormhole, selects tracked custody UTXOs, constructs the Dogecoin transaction, obtains and verifies Manager signatures, and optionally broadcasts it. Runtime endpoints and Dogecoin network are selected by the global --network flag."
)]
pub struct Args {
    /// Internal Dogecoin address network; set from global --network.
    #[arg(skip)]
    doge_network: DogeNetwork,
    /// Captured global runtime network for endpoint and identity validation.
    #[arg(skip)]
    runtime_network: RuntimeNetwork,
    /// Optional first pending request index. It must equal the previous snapshot cursor.
    #[arg(long)]
    request_index: Option<u64>,
    #[arg(long)]
    request_signature: Option<Signature>,
    #[arg(long, default_value_t = 1_000_000)]
    fee_sats: u64,
    #[arg(long, default_value_t = DUST_THRESHOLD_SATS)]
    dust_threshold_sats: u64,
    #[arg(long, help = "Solana RPC URL override")]
    solana_rpc_url: Option<String>,
    #[arg(long)]
    operator_keypair: PathBuf,
    #[arg(long)]
    payer_keypair: PathBuf,
    #[arg(long, default_value = DEFAULT_DOGE_BRIDGE)]
    doge_bridge_program: Pubkey,
    #[arg(long, default_value = DEFAULT_PENDING_MINT)]
    pending_mint_program: Pubkey,
    #[arg(long, default_value = DEFAULT_TXO_BUFFER)]
    txo_buffer_program: Pubkey,
    #[arg(long, default_value = DEFAULT_GENERIC_BUFFER)]
    generic_buffer_program: Pubkey,
    #[arg(long, help = "Wormhole Core program override")]
    wormhole_core_program: Option<Pubkey>,
    #[arg(long, help = "Wormhole Shim program override")]
    wormhole_shim_program: Option<Pubkey>,
    #[arg(long)]
    bridge_state: Option<Pubkey>,
    #[arg(long, help = "Manager HTTP service URL override")]
    manager_service_url: Option<String>,
    #[arg(long, help = "Electrs HTTP URL override")]
    electrs_url: Option<String>,
    #[arg(long, default_value_t = 500)]
    poll_interval_ms: u64,
    #[arg(long, default_value_t = 120)]
    signing_timeout_secs: u64,
    #[arg(long)]
    operator_store: PathBuf,
    #[arg(long, default_value = "/tmp/doge-process-withdrawal-evidence.json")]
    evidence_path: PathBuf,
    #[arg(
        long,
        help = "Manager set index override (default: 0 on localhost, 1 on devnet)"
    )]
    manager_set_index: Option<u32>,
    #[arg(long, default_value_t = false)]
    manager_signing_enabled: bool,
    #[arg(long, default_value_t = false)]
    broadcast_enabled: bool,
    /// Prefer the oldest durable incomplete snapshot batch before creating new work.
    #[arg(long, default_value_t = false)]
    resume: bool,
}

impl Args {
    pub fn apply_network_defaults(&mut self, network: RuntimeNetwork) {
        self.runtime_network = network;
        let defaults = network.defaults();
        self.doge_network = defaults.doge_network;
        fill_u32(&mut self.manager_set_index, defaults.manager_set_index);
        fill_string(&mut self.solana_rpc_url, defaults.solana_rpc_url);
        fill_string(&mut self.electrs_url, defaults.electrs_url);
        fill_string_optional(&mut self.manager_service_url, defaults.manager_service_url);
        if self.wormhole_core_program.is_none() {
            self.wormhole_core_program =
                Some(defaults.wormhole_core_program.parse().expect("wormhole core"));
        }
        if self.wormhole_shim_program.is_none() {
            self.wormhole_shim_program =
                Some(defaults.wormhole_shim_program.parse().expect("wormhole shim"));
        }
    }

    fn manager_set_index(&self) -> u32 {
        self.manager_set_index
            .expect("manager_set_index requires apply_network_defaults")
    }

    fn solana_rpc_url(&self) -> &str {
        self.solana_rpc_url
            .as_deref()
            .expect("solana_rpc_url requires apply_network_defaults")
    }

    fn electrs_url(&self) -> &str {
        self.electrs_url
            .as_deref()
            .expect("electrs_url requires apply_network_defaults")
    }

    fn manager_service_url(&self) -> Result<&str> {
        self.manager_service_url.as_deref().ok_or_else(|| {
            anyhow!(
                "--manager-service-url is required on --network devnet \
                 (localhost defaults to the local Manager service)"
            )
        })
    }

    fn uses_noop_shim(&self) -> bool {
        self.wormhole_core_program() == self.wormhole_shim_program()
    }

    fn validate_network_boundary(&self) -> Result<()> {
        self.runtime_network
            .validate_remote_url("Solana RPC", self.solana_rpc_url())?;
        self.runtime_network
            .validate_remote_url("Electrs", self.electrs_url())?;
        self.runtime_network
            .validate_remote_url("Manager service", self.manager_service_url()?)?;
        self.runtime_network
            .validate_manager_set(self.manager_set_index())?;
        self.runtime_network.validate_wormhole_programs(
            &self.wormhole_core_program().to_string(),
            &self.wormhole_shim_program().to_string(),
        )
    }

    fn wormhole_core_program(&self) -> Pubkey {
        self.wormhole_core_program
            .expect("wormhole_core_program requires apply_network_defaults")
    }

    fn wormhole_shim_program(&self) -> Pubkey {
        self.wormhole_shim_program
            .expect("wormhole_shim_program requires apply_network_defaults")
    }
}

#[derive(Clone, Debug)]
struct IndexedRequest {
    index: u64,
    record: WithdrawalRequestRecord,
}

#[derive(Debug)]
struct PreparedTransaction {
    transaction: UnsignedTransaction,
    unsigned_bytes: Vec<u8>,
    selected_utxos: Vec<CustodyUtxo>,
    selected_sats: u64,
    plan: CustodyTransactionPlan,
    change_script_hash: Option<[u8; 20]>,
    reservation_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterWithdrawalRequest {
    emitter_chain: u16,
    emitter_address_hex: String,
    sequence: u64,
    payload_hex: String,
    unsigned_transaction_hex: String,
    inputs: Vec<SigningInput>,
    outputs: Vec<SigningOutput>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningInput {
    original_recipient_address_hex: String,
    transaction_id_hex: String,
    vout: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningOutput {
    amount: u64,
    address_type: u32,
    address_hex: String,
}

#[derive(Debug, Deserialize)]
struct RegisterWithdrawalResponse {
    sequence: u64,
}

#[derive(Debug, Serialize)]
struct Evidence {
    schema: String,
    completed: bool,
    snapshot: Value,
    withdrawal: Value,
    manager: Value,
    dogecoin: Value,
    custody: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct ElectrsWithdrawalTransaction {
    txid: String,
    vout: Vec<ElectrsWithdrawalOutput>,
    status: ElectrsWithdrawalStatus,
}

#[derive(Debug, Clone, Deserialize)]
struct ElectrsWithdrawalOutput {
    scriptpubkey: String,
    value: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ElectrsWithdrawalStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
}

#[derive(Debug)]
struct PersistedWithdrawalGraph {
    transaction: DogecoinTransaction,
    process: ProcessWithdrawal,
    reservation: CustodyReservation,
}

#[derive(Debug)]
struct ConfirmedWithdrawal {
    transaction: ElectrsWithdrawalTransaction,
    block_height: u32,
    block_hash: [u8; 32],
    confirmations: u32,
    tx_index: u16,
}

fn plan_confirmed_withdrawal(
    transaction: ElectrsWithdrawalTransaction,
    display_txid: &str,
    block_txids: &[String],
    tip_height: u32,
) -> Result<Option<ConfirmedWithdrawal>> {
    if !transaction.txid.eq_ignore_ascii_case(display_txid) {
        bail!(
            "Electrs GET returned txid {}, expected {display_txid}",
            transaction.txid
        );
    }
    if !transaction.status.confirmed {
        return Ok(None);
    }
    let block_height = transaction
        .status
        .block_height
        .ok_or_else(|| anyhow!("confirmed Electrs transaction is missing block_height"))?;
    let block_hash_text = transaction
        .status
        .block_hash
        .as_deref()
        .ok_or_else(|| anyhow!("confirmed Electrs transaction is missing block_hash"))?;
    let block_hash = BlockHash::from_str(block_hash_text)
        .context("parse withdrawal confirmation block hash")?
        .to_byte_array();
    let tx_index = block_txids
        .iter()
        .position(|txid| txid.eq_ignore_ascii_case(display_txid))
        .ok_or_else(|| anyhow!("withdrawal transaction is absent from its confirmation block"))?;
    let tx_index =
        u16::try_from(tx_index).context("withdrawal block transaction index exceeds u16")?;
    let confirmations = tip_height
        .checked_sub(block_height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or_else(|| {
            anyhow!("Electrs tip height {tip_height} precedes withdrawal height {block_height}")
        })?;
    Ok(Some(ConfirmedWithdrawal {
        transaction,
        block_height,
        block_hash,
        confirmations,
        tx_index,
    }))
}

pub async fn run(args: Args) -> Result<()> {
    args.validate_network_boundary()?;
    let mut store = OperatorStore::open(&args.operator_store).context("open operator store")?;
    let _guard = store
        .acquire_operator_lock("process-withdrawal")
        .context("acquire withdrawal operator lock")?;
    run_with_store(args, &mut store).await
}

pub(crate) async fn run_with_store(args: Args, store: &mut OperatorStore) -> Result<()> {
    args.validate_network_boundary()?;
    if args.request_index.is_some() && args.request_signature.is_some() {
        bail!("provide at most one of --request-index or --request-signature");
    }
    let bridge_state = Pubkey::find_program_address(
        &[doge_bridge_client::constants::BRIDGE_STATE_SEED],
        &args.doge_bridge_program,
    )
    .0;
    if let Some(provided) = args.bridge_state {
        if provided != bridge_state {
            bail!("--bridge-state mismatch: expected {bridge_state}, got {provided}");
        }
    }

    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;
    let rpc =
        RpcClient::new_with_commitment(args.solana_rpc_url().to_owned(), CommitmentConfig::confirmed());
    let http = HttpClient::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("build Manager/electrs HTTP client")?;

    let incomplete = store.oldest_incomplete_snapshot_batch()?;
    if args.resume && incomplete.is_none() {
        bail!("--resume requested but the operator store has no incomplete snapshot batch");
    }
    if let Some(batch) = incomplete {
        eprintln!(
            "resuming withdrawal snapshot batch [{}, {}) at {}",
            batch.request_start_index, batch.request_end_index, batch.status
        );
        return resume_snapshot_batch(
            &args,
            store,
            &rpc,
            &http,
            bridge_state,
            &batch,
        )
        .await;
    }

    let history = load_indexed_requests(&args, bridge_state).await?;
    let state_before = read_bridge_state(&rpc, bridge_state, args.doge_bridge_program).await?;
    let request_start = state_before
        .withdrawal_snapshot
        .next_requested_withdrawals_tree_index;
    let requested_tip = state_before.requested_withdrawals_tree.next_index;
    let request_end = capped_batch_end(request_start, requested_tip);
    if request_start >= request_end {
        bail!("no withdrawal requests after the current snapshot");
    }
    if history.len() as u64 != requested_tip {
        bail!(
            "withdrawal history tip {} does not match on-chain requested tip {requested_tip}",
            history.len()
        );
    }
    if let Some(index) = args.request_index {
        if index != request_start {
            bail!("--request-index {index} is not the snapshot cursor {request_start}");
        }
    }
    if let Some(signature) = args.request_signature.as_ref() {
        let first = history.get(request_start as usize).ok_or_else(|| {
            anyhow!("withdrawal history does not contain request {request_start}")
        })?;
        if &first.record.signature != signature {
            bail!("--request-signature does not identify the first unsnapshotted withdrawal");
        }
    }

    let all_leaves = history
        .iter()
        .map(|request| {
            PsyWithdrawalRequest::new(
                request.record.recipient_address,
                request.record.net_amount_sats,
                request.record.address_type,
            )
        })
        .collect::<Vec<_>>();
    let proof_bytes = SnapshotWithdrawalProof::from_tree_leaves(
        &all_leaves,
        request_start,
        request_end,
    )
    .ok_or_else(|| anyhow!("build withdrawal snapshot range proof"))?;
    let requested_tree_root = SnapshotWithdrawalProof::compute_root(
        request_start,
        request_end,
        &proof_bytes,
    )
    .ok_or_else(|| anyhow!("reconstruct requested-withdrawals tip root"))?;
    if requested_tree_root != state_before.requested_withdrawals_tree.get_root() {
        bail!("reconstructed withdrawal history root differs from on-chain requested tree");
    }
    let snapshot_root = SnapshotWithdrawalProof::compute_prefix_root(
        request_start,
        request_end,
        &proof_bytes,
    )
    .ok_or_else(|| anyhow!("reconstruct withdrawal snapshot prefix root"))?;

    let requests = history_range(&history, request_start, request_end)?;
    let payload = payload_for_requests(&requests, args.manager_set_index())?;
    let payload_bytes = payload.serialize()?;
    let payload_hash = hash_sha256(&payload_bytes);
    record_requests(store, &requests)?;

    let utx0_buffer = create_generic_buffer(
        &rpc,
        &payer,
        &operator,
        args.generic_buffer_program,
        &payload_bytes,
    )
    .await?;
    verify_generic_buffer(
        &rpc,
        utx0_buffer,
        args.generic_buffer_program,
        operator.pubkey(),
        &payload_bytes,
    )
    .await?;
    let proof_buffer = create_generic_buffer(
        &rpc,
        &payer,
        &operator,
        args.generic_buffer_program,
        &proof_bytes,
    )
    .await?;
    verify_generic_buffer(
        &rpc,
        proof_buffer,
        args.generic_buffer_program,
        operator.pubkey(),
        &proof_bytes,
    )
    .await?;

    let sequence = if args.uses_noop_shim() {
        request_start
    } else {
        read_wormhole_sequence(&rpc, bridge_state, args.wormhole_core_program())
            .await?
            .unwrap_or(0)
    };
    let manager_set = manager_set_for_index(args.manager_set_index())?;
    let reservation_id = format!(
        "withdrawal-snapshot-{request_start}-{request_end}-{}",
        Signature::new_unique()
    );
    let withdrawal_sats = payload.outputs.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.amount)
            .ok_or_else(|| anyhow!("withdrawal amount overflow"))
    })?;
    let required_sats = withdrawal_sats
        .checked_add(args.fee_sats)
        .ok_or_else(|| anyhow!("required custody amount overflow"))?;

    let manager_set_account = manager_set_pda(args.manager_set_index())?;
    let snapshot_instruction = instructions::snapshot_withdrawals(
        args.doge_bridge_program,
        operator.pubkey(),
        utx0_buffer,
        proof_buffer,
        manager_set_account,
        args.wormhole_shim_program(),
        args.wormhole_core_program(),
        SnapshotWithdrawalsInstructionData {
            expected_request_start: request_start,
            expected_request_end: request_end,
            manager_set_index: args.manager_set_index(),
            _padding: [0; 4],
            expected_wormhole_sequence: sequence,
            expected_requested_tree_root: requested_tree_root,
            expected_snapshot_root: snapshot_root,
            expected_payload_hash: payload_hash,
        },
    );
    let (fee_collector, _) =
        Pubkey::find_program_address(&[b"fee_collector"], &args.wormhole_core_program());
    ensure_fee_collector_funding(&rpc, &payer, fee_collector).await?;
    ensure_operator_fee_funding(&rpc, &payer, &operator).await?;
    let fee_prepay = system_instruction::transfer(
        &operator.pubkey(),
        &fee_collector,
        WORMHOLE_FEE_PREPAY_LAMPORTS,
    );
    let blockhash = rpc.get_latest_blockhash().await?;
    let snapshot_transaction = signed_solana_transaction(
        &payer,
        &[
            ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(SNAPSHOT_COMPUTE_UNITS),
            fee_prepay,
            snapshot_instruction,
        ],
        &[&operator],
        blockhash,
    );
    let snapshot_signature = *snapshot_transaction
        .signatures
        .first()
        .ok_or_else(|| anyhow!("signed snapshot transaction has no signature"))?;
    let solana_transaction = bincode::serialize(&snapshot_transaction)?;
    let payload_bytes_for_batch = payload_bytes.clone();
    let reservation_id_for_batch = reservation_id.clone();
    let (reservation, mut batch) = store
        .reserve_custody_for_snapshot(&reservation_id, required_sats, |reservation| {
            let prepared = prepared_from_reservation(
                &args,
                bridge_state,
                &payload,
                &manager_set,
                reservation.clone(),
                None,
            )
            .map_err(|error| {
                doge_bridge_client::operator_store::OperatorStoreError::InvalidTransition(
                    error.to_string(),
                )
            })?;
            Ok(SnapshotBatch {
                solana_signature: snapshot_signature.to_string(),
                solana_slot: 0,
                block_time: None,
                request_start_index: request_start,
                request_end_index: request_end,
                snapshot_root,
                payload: payload_bytes_for_batch,
                payload_hash,
                wormhole_sequence: sequence,
                solana_transaction: Some(solana_transaction),
                unsigned_transaction: Some(prepared.unsigned_bytes),
                reservation_id: Some(reservation_id_for_batch),
                status: OperatorStatus::Observed,
            })
        })
        .context("atomically reserve custody and persist observed snapshot")?;
    if batch.reservation_id.as_deref() != Some(&reservation.reservation_id) {
        bail!("atomic observed persistence returned a mismatched reservation");
    }

    let returned_signature = rpc
        .send_transaction(&snapshot_transaction)
        .await
        .context("submit persisted snapshot_withdrawals transaction")?;
    if returned_signature != snapshot_signature {
        bail!(
            "Solana RPC returned snapshot signature {returned_signature}, expected {snapshot_signature}"
        );
    }
    confirm_snapshot_batch(&args, store, &rpc, bridge_state, &mut batch).await?;
    continue_snapshot_batch(&args, store, &http, bridge_state, &batch).await
}

fn capped_batch_end(snapshot_cursor: u64, requested_tip: u64) -> u64 {
    snapshot_cursor
        .saturating_add(SNAPSHOT_PROOF_MAX_BATCH as u64)
        .min(requested_tip)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedBatchAction {
    AwaitConfirmation,
    ResendOriginal,
    Fail,
    Wait,
}

fn select_observed_batch_action(
    status: Option<bool>,
    metadata_found: bool,
    blockhash_valid: bool,
    snapshot_cursor: u64,
    request_start: u64,
) -> ObservedBatchAction {
    if status == Some(false) {
        if snapshot_cursor == request_start {
            ObservedBatchAction::Fail
        } else {
            ObservedBatchAction::Wait
        }
    } else if metadata_found || status == Some(true) {
        ObservedBatchAction::AwaitConfirmation
    } else if blockhash_valid {
        ObservedBatchAction::ResendOriginal
    } else if snapshot_cursor == request_start {
        ObservedBatchAction::Fail
    } else {
        ObservedBatchAction::Wait
    }
}

fn apply_observed_terminal_effect(
    store: &mut OperatorStore,
    batch: &SnapshotBatch,
    action: ObservedBatchAction,
) -> Result<()> {
    match action {
        ObservedBatchAction::Fail => {
            if let Some(reservation_id) = batch.reservation_id.as_deref() {
                if let Some(reservation) = store.load_reservation(reservation_id)? {
                    if reservation.status == CustodyReservationStatus::Reserved {
                        store.release_reservation(reservation_id)?;
                    }
                }
            }
            store.set_snapshot_batch_status(&batch.solana_signature, OperatorStatus::Failed)?;
            bail!(
                "persisted snapshot {} failed or expired before advancing the cursor",
                batch.solana_signature
            );
        }
        ObservedBatchAction::Wait => bail!(
            "persisted snapshot {} has ambiguous chain status; refusing a new blockhash",
            batch.solana_signature
        ),
        ObservedBatchAction::AwaitConfirmation | ObservedBatchAction::ResendOriginal => Ok(()),
    }
}

async fn resume_snapshot_batch(
    args: &Args,
    store: &mut OperatorStore,
    rpc: &RpcClient,
    http: &HttpClient,
    bridge_state: Pubkey,
    stored: &SnapshotBatch,
) -> Result<()> {
    let mut batch = stored.clone();
    if batch.status == OperatorStatus::Observed {
        let transaction_bytes = batch
            .solana_transaction
            .as_deref()
            .ok_or_else(|| anyhow!("observed snapshot batch has no persisted Solana transaction"))?;
        let transaction: Transaction = bincode::deserialize(transaction_bytes)
            .context("decode persisted snapshot Solana transaction")?;
        if bincode::serialize(&transaction)? != transaction_bytes {
            bail!("persisted snapshot Solana transaction is not canonical bincode");
        }
        let signature = transaction
            .signatures
            .first()
            .copied()
            .ok_or_else(|| anyhow!("persisted snapshot transaction has no signature"))?;
        if signature.to_string() != batch.solana_signature {
            bail!("persisted snapshot transaction signature differs from snapshot batch key");
        }

        let state = read_bridge_state(rpc, bridge_state, args.doge_bridge_program).await?;
        let snapshot_cursor = state
            .withdrawal_snapshot
            .next_requested_withdrawals_tree_index;
        let status = rpc
            .get_signature_statuses_with_history(&[signature])
            .await
            .context("query persisted snapshot signature status")?
            .value
            .into_iter()
            .next()
            .flatten();
        let metadata = rpc
            .get_transaction(&signature, UiTransactionEncoding::Base64)
            .await
            .ok();
        let blockhash_valid = if status.is_none() && metadata.is_none() {
            rpc.is_blockhash_valid(&transaction.message.recent_blockhash, rpc.commitment())
                .await
                .context("check persisted snapshot blockhash")?
        } else {
            false
        };
        let action = select_observed_batch_action(
            status.as_ref().map(|value| value.err.is_none()),
            metadata.is_some(),
            blockhash_valid,
            snapshot_cursor,
            batch.request_start_index,
        );
        match action {
            ObservedBatchAction::AwaitConfirmation => {}
            ObservedBatchAction::ResendOriginal => {
                let returned = rpc
                    .send_transaction(&transaction)
                    .await
                    .context("resend persisted snapshot transaction")?;
                if returned != signature {
                    bail!("resubmitted snapshot returned a different signature");
                }
            }
            ObservedBatchAction::Fail | ObservedBatchAction::Wait => {
                return apply_observed_terminal_effect(store, &batch, action);
            }
        }
        if let Some(metadata) = metadata {
            finish_confirmed_snapshot(args, store, rpc, bridge_state, &mut batch, metadata).await?;
        } else {
            confirm_snapshot_batch(args, store, rpc, bridge_state, &mut batch).await?;
        }
    }
    continue_snapshot_batch(args, store, http, bridge_state, &batch).await
}

async fn confirm_snapshot_batch(
    args: &Args,
    store: &mut OperatorStore,
    rpc: &RpcClient,
    bridge_state: Pubkey,
    batch: &mut SnapshotBatch,
) -> Result<()> {
    let signature = Signature::from_str(&batch.solana_signature)?;
    let metadata = wait_for_transaction_meta(rpc, &signature, Duration::from_secs(30)).await?;
    finish_confirmed_snapshot(args, store, rpc, bridge_state, batch, metadata).await
}

async fn finish_confirmed_snapshot(
    args: &Args,
    store: &mut OperatorStore,
    rpc: &RpcClient,
    bridge_state: Pubkey,
    batch: &mut SnapshotBatch,
    metadata: solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta,
) -> Result<()> {
    let state = read_bridge_state(rpc, bridge_state, args.doge_bridge_program).await?;
    let cursor = state
        .withdrawal_snapshot
        .next_requested_withdrawals_tree_index;
    if metadata
        .transaction
        .meta
        .as_ref()
        .is_some_and(|meta| meta.err.is_some())
    {
        if cursor == batch.request_start_index {
            if let Some(reservation_id) = batch.reservation_id.as_deref() {
                if let Some(reservation) = store.load_reservation(reservation_id)? {
                    if reservation.status == CustodyReservationStatus::Reserved {
                        store.release_reservation(reservation_id)?;
                    }
                }
            }
            store.set_snapshot_batch_status(&batch.solana_signature, OperatorStatus::Failed)?;
            bail!("persisted snapshot transaction failed before advancing the cursor");
        }
        bail!("persisted snapshot transaction failed but the cursor state is ambiguous");
    }
    if cursor != batch.request_end_index {
        bail!(
            "confirmed snapshot cursor {cursor} does not equal persisted batch end {}",
            batch.request_end_index
        );
    }
    if state
        .withdrawal_snapshot
        .requested_withdrawals_tree_root
        != batch.snapshot_root
    {
        bail!("confirmed snapshot root differs from the persisted batch root");
    }
    let signature = Signature::from_str(&batch.solana_signature)?;
    let noop = find_noop_message(args, bridge_state, &signature).await?;
    if noop.emitter != bridge_state || noop.doge_tx_bytes != batch.payload {
        bail!("snapshot Wormhole message differs from the persisted batch");
    }
    if args.uses_noop_shim() {
        if u64::from(noop.nonce) != batch.wormhole_sequence {
            bail!("snapshot noop sequence differs from the persisted batch");
        }
    } else {
        let after = read_wormhole_sequence(rpc, bridge_state, args.wormhole_core_program())
            .await?
            .ok_or_else(|| anyhow!("Wormhole sequence account missing after snapshot"))?;
        let expected_after = batch
            .wormhole_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("Wormhole sequence overflow"))?;
        if after != expected_after {
            bail!(
                "Wormhole sequence is {after}, expected exactly {expected_after} for persisted batch"
            );
        }
    }
    batch.solana_slot = metadata.slot;
    batch.block_time = metadata.block_time;
    batch.status = if batch.unsigned_transaction.is_some() {
        OperatorStatus::Constructed
    } else {
        OperatorStatus::Snapshotted
    };
    store.upsert_snapshot_batch(batch)?;
    for request_index in batch.request_start_index..batch.request_end_index {
        store.set_withdrawal_request_status(request_index, batch.status)?;
    }
    Ok(())
}

fn load_persisted_withdrawal_graph(
    store: &OperatorStore,
    batch: &SnapshotBatch,
) -> Result<PersistedWithdrawalGraph> {
    let reservation_id = batch
        .reservation_id
        .as_deref()
        .ok_or_else(|| anyhow!("persisted snapshot batch has no custody reservation"))?;
    let reservation = store
        .load_reservation(reservation_id)?
        .ok_or_else(|| anyhow!("snapshot custody reservation {reservation_id} is missing"))?;
    let process = store
        .process_withdrawal_by_signature(&batch.solana_signature)?
        .ok_or_else(|| anyhow!("signed snapshot batch has no process-withdrawal record"))?;
    if process.solana_signature != batch.solana_signature
        || process.request_start_index != batch.request_start_index
        || process.request_end_index != batch.request_end_index
        || process.snapshot_root != batch.snapshot_root
    {
        bail!("persisted signed process-withdrawal record drifted from snapshot batch");
    }
    let transaction = store
        .dogecoin_transaction_by_process_signature(&batch.solana_signature)?
        .ok_or_else(|| anyhow!("signed snapshot batch has no linked Dogecoin transaction"))?;
    if transaction.raw_hash != process.dogecoin_raw_hash {
        bail!("persisted signed Dogecoin transaction raw hash drifted");
    }
    let internal_txid = transaction
        .txid
        .ok_or_else(|| anyhow!("persisted signed Dogecoin transaction has no txid"))?;
    let mappings = store.mappings_by_process_signature(&batch.solana_signature)?;
    let expected_mapping_count = usize::try_from(
        batch
            .request_end_index
            .checked_sub(batch.request_start_index)
            .ok_or_else(|| anyhow!("persisted snapshot request range underflow"))?,
    )
    .context("persisted snapshot request count exceeds usize")?;
    if mappings.len() != expected_mapping_count
        || mappings.iter().enumerate().any(|(offset, mapping)| {
            mapping.request_index != batch.request_start_index + offset as u64
                || mapping.process_solana_signature != batch.solana_signature
                || mapping.dogecoin_txid != internal_txid
        })
    {
        bail!("persisted signed request-to-Dogecoin mappings are incomplete or drifted");
    }
    if reservation.utxos.is_empty()
        || reservation.request_index != Some(batch.request_start_index)
        || reservation.process_solana_signature.as_deref() != Some(&batch.solana_signature)
        || reservation.utxos.iter().any(|utxo| {
            utxo.reservation_id.as_deref() != Some(reservation_id)
                || utxo.spend_request_index != Some(batch.request_start_index)
                || utxo.spend_process_signature.as_deref() != Some(&batch.solana_signature)
        })
    {
        bail!("persisted signed custody links are incomplete or drifted");
    }
    Ok(PersistedWithdrawalGraph {
        transaction,
        process,
        reservation,
    })
}

fn load_complete_signed_graph(
    store: &OperatorStore,
    batch: &SnapshotBatch,
) -> Result<PersistedWithdrawalGraph> {
    if batch.status != OperatorStatus::Signed {
        bail!("snapshot batch {} is not signed", batch.solana_signature);
    }
    let graph = load_persisted_withdrawal_graph(store, batch)?;
    if graph.transaction.status != OperatorStatus::Signed
        || graph.process.status != OperatorStatus::Signed
        || graph.reservation.status != CustodyReservationStatus::Reserved
        || graph.reservation.spend_txid.is_some()
        || graph.reservation.utxos.iter().any(|utxo| {
            utxo.status != CustodyUtxoStatus::Reserved || utxo.spend_txid.is_some()
        })
    {
        bail!("persisted Signed graph has incomplete or drifted statuses");
    }
    for request_index in batch.request_start_index..batch.request_end_index {
        let request = store
            .withdrawal_request_by_index(request_index)?
            .ok_or_else(|| anyhow!("persisted signed request {request_index} is missing"))?;
        if request.status != OperatorStatus::Signed {
            bail!("persisted signed request {request_index} status drifted");
        }
    }
    Ok(graph)
}

async fn continue_snapshot_batch(
    args: &Args,
    store: &mut OperatorStore,
    http: &HttpClient,
    bridge_state: Pubkey,
    batch: &SnapshotBatch,
) -> Result<()> {
    let payload = Utx0UnlockPayload::parse(&batch.payload)?;
    if payload.destination_chain != DOGECOIN_CHAIN_ID
        || payload.delegated_manager_set_index != args.manager_set_index()
        || hash_sha256(&batch.payload) != batch.payload_hash
    {
        bail!("persisted snapshot payload identity mismatch");
    }
    if batch.status == OperatorStatus::Broadcast {
        return resume_broadcast_batch(args, store, http, batch, &payload).await;
    }
    if batch.status == OperatorStatus::Signed {
        let graph = load_persisted_withdrawal_graph(store, batch)?;
        if broadcast_transition_started(&graph) {
            complete_broadcast_transition(store, batch, &graph)?;
            let broadcast_batch = store
                .snapshot_batch_by_signature(&batch.solana_signature)?
                .ok_or_else(|| anyhow!("broadcast snapshot batch disappeared"))?;
            return resume_broadcast_batch(args, store, http, &broadcast_batch, &payload).await;
        }
        let graph = load_complete_signed_graph(store, batch)?;
        return resume_signed_batch(args, store, http, batch, &payload, graph).await;
    }

    let manager_set = manager_set_for_index(payload.delegated_manager_set_index)?;
    let reservation_id = batch
        .reservation_id
        .as_deref()
        .ok_or_else(|| anyhow!("snapshot batch has no custody reservation"))?;
    let reservation = store
        .load_reservation(reservation_id)?
        .ok_or_else(|| anyhow!("snapshot custody reservation {reservation_id} is missing"))?;
    let persisted_unsigned = batch
        .unsigned_transaction
        .as_deref()
        .ok_or_else(|| anyhow!("snapshot batch has no unsigned Dogecoin transaction"))?;
    let mut prepared = prepared_from_reservation(
        args,
        bridge_state,
        &payload,
        &manager_set,
        reservation,
        Some(persisted_unsigned),
    )?;

    if args.manager_signing_enabled {
        register_unsigned_transaction(
            http,
            args.manager_service_url()?,
            bridge_state,
            batch.wormhole_sequence,
            &batch.payload,
            &prepared,
        )
        .await?;
    }
    let signatures = if args.manager_signing_enabled {
        wait_for_manager_signatures(
            http,
            args.manager_service_url()?,
            &bridge_state.to_bytes(),
            batch.wormhole_sequence,
            Duration::from_millis(args.poll_interval_ms),
            Duration::from_secs(args.signing_timeout_secs),
        )
        .await?
    } else {
        fetch_manager_signatures(
            http,
            args.manager_service_url()?,
            SOLANA_EMITTER_CHAIN,
            &bridge_state.to_bytes(),
            batch.wormhole_sequence,
        )
        .await?
    };
    let signed_vaa = fetch_signed_vaa(
        http,
        args.manager_service_url()?,
        SOLANA_EMITTER_CHAIN,
        &bridge_state.to_bytes(),
        batch.wormhole_sequence,
    )
    .await?;
    assert_vaa_and_manager(
        &signed_vaa,
        &signatures,
        bridge_state,
        batch.wormhole_sequence,
        &payload,
        &manager_set,
    )?;
    apply_manager_signatures(&mut prepared.transaction, &signatures, &manager_set)?;
    let signed_bytes = prepared.transaction.serialize();
    let raw_hash = hash_sha256(&signed_bytes);
    let internal_txid = double_sha256(&signed_bytes);
    let display_txid = hex::encode(prepared.transaction.txid());

    let dogecoin_transaction = DogecoinTransaction {
        raw_hash,
        txid: Some(internal_txid),
        raw_transaction: Some(signed_bytes.clone()),
        status: OperatorStatus::Signed,
        block_hash: None,
        block_height: None,
        confirmations: 0,
    };
    let process_withdrawal = ProcessWithdrawal {
        solana_signature: batch.solana_signature.clone(),
        solana_slot: batch.solana_slot,
        block_time: batch.block_time,
        request_start_index: batch.request_start_index,
        request_end_index: batch.request_end_index,
        snapshot_root: batch.snapshot_root,
        dogecoin_raw_hash: raw_hash,
        return_output_index: payload.outputs.len() as u64,
        return_output_amount_sats: prepared.plan.change_sats,
        old_spent_txo_root: [0; 32],
        new_spent_txo_root: [0; 32],
        status: OperatorStatus::Signed,
    };
    store.persist_signed_snapshot(
        &batch.solana_signature,
        &prepared.reservation_id,
        &dogecoin_transaction,
        &process_withdrawal,
    )?;
    let broadcast_txid = if args.broadcast_enabled {
        mark_batch_broadcast(
            store,
            http,
            args,
            batch,
            &prepared.reservation_id,
            &signed_bytes,
            raw_hash,
            internal_txid,
            &display_txid,
        )
        .await?;
        display_txid.clone()
    } else {
        display_txid.clone()
    };

    let evidence = Evidence {
        schema: "doge-process-withdrawal-v5-durable-snapshot".into(),
        completed: args.broadcast_enabled,
        snapshot: json!({
            "signature": batch.solana_signature,
            "slot": batch.solana_slot,
            "requestStart": batch.request_start_index,
            "requestEnd": batch.request_end_index,
            "snapshotRootHex": hex::encode(batch.snapshot_root),
            "sequence": batch.wormhole_sequence,
            "payloadHex": hex::encode(&batch.payload),
        }),
        withdrawal: json!({
            "outputCount": payload.outputs.len(),
            "outputs": payload.outputs.iter().map(|output| json!({
                "recipientAddressHex": hex::encode(output.address),
                "amountSats": output.amount,
                "addressType": output.address_type as u32,
            })).collect::<Vec<_>>(),
        }),
        manager: json!({
            "serviceUrl": args.manager_service_url()?,
            "vaaHashHex": hex::encode(signatures.vaa_hash),
            "signedVaaSha256Hex": hex::encode(hash_sha256(&signed_vaa)),
            "required": signatures.required,
            "total": signatures.total,
            "signerIndices": signatures.signatures.iter().map(|s| s.signer_index).collect::<Vec<_>>(),
        }),
        dogecoin: json!({
            "unsignedTransactionHex": hex::encode(&prepared.unsigned_bytes),
            "signedTransactionHex": hex::encode(&signed_bytes),
            "txid": broadcast_txid,
            "broadcast": args.broadcast_enabled,
        }),
        custody: json!({
            "reservationId": prepared.reservation_id,
            "selectedSats": prepared.selected_sats,
            "minerFeeSats": args.fee_sats,
            "changeSats": prepared.plan.change_sats,
            "changeScriptHashHex": prepared.change_script_hash.map(hex::encode),
            "inputs": prepared.selected_utxos.iter().map(|utxo| json!({
                "txidInternalHex": hex::encode(utxo.txid),
                "vout": utxo.vout,
                "amountSats": utxo.amount_sats,
            })).collect::<Vec<_>>(),
        }),
    };
    write_evidence(&args.evidence_path, &evidence)
}


async fn resume_signed_batch(
    args: &Args,
    store: &mut OperatorStore,
    http: &HttpClient,
    batch: &SnapshotBatch,
    payload: &Utx0UnlockPayload,
    graph: PersistedWithdrawalGraph,
) -> Result<()> {
    let transaction = graph.transaction;
    let signed_bytes = transaction
        .raw_transaction
        .as_deref()
        .ok_or_else(|| anyhow!("signed Dogecoin transaction has no persisted raw bytes"))?;
    let raw_hash = hash_sha256(signed_bytes);
    if raw_hash != transaction.raw_hash {
        bail!("persisted signed Dogecoin raw hash mismatch");
    }
    let internal_txid = double_sha256(signed_bytes);
    if transaction.txid != Some(internal_txid) {
        bail!("persisted signed Dogecoin txid mismatch");
    }
    let mut display = internal_txid;
    display.reverse();
    let display_txid = hex::encode(display);
    let reservation_id = graph.reservation.reservation_id.as_str();
    if args.broadcast_enabled {
        mark_batch_broadcast(
            store,
            http,
            args,
            batch,
            reservation_id,
            signed_bytes,
            raw_hash,
            internal_txid,
            &display_txid,
        )
        .await?;
    }
    let evidence = Evidence {
        schema: "doge-process-withdrawal-v5-durable-snapshot".into(),
        completed: args.broadcast_enabled,
        snapshot: json!({
            "signature": batch.solana_signature,
            "slot": batch.solana_slot,
            "requestStart": batch.request_start_index,
            "requestEnd": batch.request_end_index,
            "snapshotRootHex": hex::encode(batch.snapshot_root),
            "sequence": batch.wormhole_sequence,
            "payloadHex": hex::encode(&batch.payload),
            "resumedAtSignedStage": true,
        }),
        withdrawal: json!({"outputCount": payload.outputs.len()}),
        manager: json!({"reusedPersistedSignedTransaction": true}),
        dogecoin: json!({
            "signedTransactionHex": hex::encode(signed_bytes),
            "txid": display_txid,
            "broadcast": args.broadcast_enabled,
        }),
        custody: json!({"reservationId": reservation_id}),
    };
    write_evidence(&args.evidence_path, &evidence)
}
async fn resume_broadcast_batch(
    args: &Args,
    store: &mut OperatorStore,
    http: &HttpClient,
    batch: &SnapshotBatch,
    payload: &Utx0UnlockPayload,
) -> Result<()> {
    let graph = load_persisted_withdrawal_graph(store, batch)?;
    let transaction = &graph.transaction;
    let signed_bytes = transaction
        .raw_transaction
        .as_deref()
        .ok_or_else(|| anyhow!("broadcast Dogecoin transaction has no persisted raw bytes"))?;
    let internal_txid = transaction
        .txid
        .ok_or_else(|| anyhow!("broadcast Dogecoin transaction has no txid"))?;
    if hash_sha256(signed_bytes) != transaction.raw_hash
        || double_sha256(signed_bytes) != internal_txid
    {
        bail!("persisted broadcast Dogecoin transaction identity mismatch");
    }
    if graph.process.status != OperatorStatus::Broadcast
        || transaction.status != OperatorStatus::Broadcast
        || graph.reservation.status != CustodyReservationStatus::Broadcast
        || graph.reservation.spend_txid != Some(internal_txid)
    {
        bail!("persisted Broadcast graph has incomplete or drifted statuses");
    }
    for request_index in batch.request_start_index..batch.request_end_index {
        let request = store
            .withdrawal_request_by_index(request_index)?
            .ok_or_else(|| anyhow!("persisted broadcast request {request_index} is missing"))?;
        if request.status != OperatorStatus::Broadcast {
            bail!("persisted broadcast request {request_index} status drifted");
        }
    }
    let mut display = internal_txid;
    display.reverse();
    let display_txid = hex::encode(display);
    let Some(confirmed) = fetch_confirmed_withdrawal(
        http,
        args.electrs_url(),
        &display_txid,
    )
    .await?
    else {
        bail!("broadcast Dogecoin transaction {display_txid} is not yet confirmed");
    };
    let change = derive_confirmed_change(
        args.doge_network,
        batch,
        &graph,
        payload.outputs.len(),
        &confirmed,
    )?;
    let confirmed_transaction = DogecoinTransaction {
        status: OperatorStatus::Confirmed,
        block_hash: Some(confirmed.block_hash),
        block_height: Some(confirmed.block_height),
        confirmations: confirmed.confirmations,
        ..transaction.clone()
    };
    store.finalize_confirmed_snapshot(
        &batch.solana_signature,
        &confirmed_transaction,
        change.as_ref(),
    )?;
    Ok(())
}

async fn fetch_confirmed_withdrawal(
    client: &HttpClient,
    electrs_url: &str,
    display_txid: &str,
) -> Result<Option<ConfirmedWithdrawal>> {
    let transaction: ElectrsWithdrawalTransaction = electrs_get_json(
        client,
        format!("{}/tx/{display_txid}", electrs_url.trim_end_matches('/')),
    )
    .await?;
    if !transaction.txid.eq_ignore_ascii_case(display_txid) {
        bail!(
            "Electrs GET returned txid {}, expected {display_txid}",
            transaction.txid
        );
    }
    if !transaction.status.confirmed {
        return Ok(None);
    }
    let block_hash_text = transaction
        .status
        .block_hash
        .as_deref()
        .ok_or_else(|| anyhow!("confirmed Electrs transaction is missing block_hash"))?;
    let block_txids: Vec<String> = electrs_get_json(
        client,
        format!(
            "{}/block/{block_hash_text}/txids",
            electrs_url.trim_end_matches('/')
        ),
    )
    .await?;
    let tip_height = electrs_get_height(client, electrs_url).await?;
    plan_confirmed_withdrawal(transaction, display_txid, &block_txids, tip_height)
}

fn derive_confirmed_change(
    network: DogeNetwork,
    batch: &SnapshotBatch,
    graph: &PersistedWithdrawalGraph,
    withdrawal_output_count: usize,
    confirmed: &ConfirmedWithdrawal,
) -> Result<Option<CustodyUtxo>> {
    if graph.process.return_output_amount_sats == 0 {
        if confirmed.transaction.vout.len() != withdrawal_output_count {
            bail!("zero-change confirmed transaction has an unexpected output count");
        }
        return Ok(None);
    }
    let expected_vout = u32::try_from(withdrawal_output_count)
        .context("withdrawal output count exceeds u32")?;
    if graph.process.return_output_index != u64::from(expected_vout) {
        bail!("persisted change output index is not the last prepared output");
    }
    if confirmed.transaction.vout.len() != withdrawal_output_count + 1 {
        bail!("confirmed transaction does not end with exactly one change output");
    }
    let output = confirmed
        .transaction
        .vout
        .last()
        .ok_or_else(|| anyhow!("confirmed transaction has no change output"))?;
    if output.value != graph.process.return_output_amount_sats {
        bail!("confirmed change value differs from prepared plan");
    }
    let script = hex::decode(&output.scriptpubkey).context("decode confirmed change script")?;
    if script.len() != 23 || script[..2] != [0xa9, 0x14] || script[22] != 0x87 {
        bail!("confirmed change output is not P2SH");
    }
    let mut script_hash = [0u8; 20];
    script_hash.copy_from_slice(&script[2..22]);
    let unsigned_bytes = batch
        .unsigned_transaction
        .as_deref()
        .ok_or_else(|| anyhow!("broadcast snapshot batch has no unsigned transaction"))?;
    let selected_inputs = graph
        .reservation
        .utxos
        .iter()
        .map(|utxo| SelectedUtxo {
            transaction_id: {
                let mut display = utxo.txid;
                display.reverse();
                display
            },
            vout: utxo.vout,
            redeem_script: vec![0x51],
        })
        .collect();
    let recovered = UnsignedTransaction::from_persisted_bytes(unsigned_bytes, selected_inputs)?;
    let prepared_change = recovered
        .outputs()
        .last()
        .ok_or_else(|| anyhow!("prepared transaction has no change output"))?;
    if prepared_change.amount != output.value
        || prepared_change.address_type != UtxoAddressType::P2sh
        || prepared_change.address != script_hash
    {
        bail!("confirmed change output differs from prepared transaction");
    }
    let key_reference = graph
        .reservation
        .utxos
        .first()
        .map(|utxo| utxo.key_reference.clone())
        .ok_or_else(|| anyhow!("broadcast reservation has no selected custody inputs"))?;
    if graph
        .reservation
        .utxos
        .iter()
        .any(|utxo| utxo.key_reference != key_reference)
    {
        bail!("selected custody inputs have inconsistent key references");
    }
    let vout = u16::try_from(expected_vout).context("withdrawal change vout exceeds u16")?;
    let internal_txid = graph.transaction.txid.expect("validated transaction txid");
    Ok(Some(CustodyUtxo {
        txid: internal_txid,
        vout: expected_vout,
        amount_sats: output.value,
        script_pubkey_hex: hex::encode(&script),
        custody_address: network.encode_address(1, script_hash)?,
        key_reference,
        confirmation_block_hash: Some(confirmed.block_hash),
        confirmation_height: Some(confirmed.block_height),
        confirmations: confirmed.confirmations,
        leaf_index: custody_ops::compute_combined_index(
            confirmed.block_height,
            confirmed.tx_index,
            vout,
        ),
        status: CustodyUtxoStatus::Available,
        reservation_id: None,
        spend_txid: None,
        source_deposit_txid: None,
        source_solana_signature: Some(batch.solana_signature.clone()),
        spend_request_index: None,
        spend_process_signature: None,
        original_recipient_address: [0; 32],
    }))
}

async fn electrs_get_height(client: &HttpClient, electrs_url: &str) -> Result<u32> {
    let url = format!("{}/blocks/tip/height", electrs_url.trim_end_matches('/'));
    let response = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response.text().await.with_context(|| format!("read {url}"))?;
    if !status.is_success() {
        bail!("Electrs GET {url} returned {status}: {body}");
    }
    body.trim()
        .parse::<u32>()
        .with_context(|| format!("parse Electrs tip height from {body:?}"))
}

async fn electrs_get_json<T: DeserializeOwned>(
    client: &HttpClient,
    url: String,
) -> Result<T> {
    let response = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response.text().await.with_context(|| format!("read {url}"))?;
    if !status.is_success() {
        bail!("Electrs GET {url} returned {status}: {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("decode Electrs response from {url}"))
}


async fn mark_batch_broadcast(
    store: &mut OperatorStore,
    http: &HttpClient,
    args: &Args,
    batch: &SnapshotBatch,
    reservation_id: &str,
    signed_bytes: &[u8],
    raw_hash: [u8; 32],
    internal_txid: [u8; 32],
    display_txid: &str,
) -> Result<()> {
    broadcast_electrs_idempotent(http, args.electrs_url(), signed_bytes, display_txid).await?;
    let graph = load_persisted_withdrawal_graph(store, batch)?;
    if graph.reservation.reservation_id != reservation_id
        || graph.transaction.raw_hash != raw_hash
        || graph.transaction.txid != Some(internal_txid)
    {
        bail!("persisted Signed graph differs before Broadcast transition");
    }
    complete_broadcast_transition(store, batch, &graph)
}

fn broadcast_transition_started(graph: &PersistedWithdrawalGraph) -> bool {
    graph.reservation.status == CustodyReservationStatus::Broadcast
        || graph.transaction.status == OperatorStatus::Broadcast
        || graph.process.status == OperatorStatus::Broadcast
        || graph
            .reservation
            .utxos
            .iter()
            .any(|utxo| utxo.status == CustodyUtxoStatus::Broadcast)
}

fn complete_broadcast_transition(
    store: &mut OperatorStore,
    batch: &SnapshotBatch,
    graph: &PersistedWithdrawalGraph,
) -> Result<()> {
    let internal_txid = graph
        .transaction
        .txid
        .ok_or_else(|| anyhow!("signed transaction has no txid during Broadcast recovery"))?;
    match graph.reservation.status {
        CustodyReservationStatus::Reserved => {
            store.mark_reservation_broadcast(&graph.reservation.reservation_id, &internal_txid)?;
        }
        CustodyReservationStatus::Broadcast if graph.reservation.spend_txid == Some(internal_txid) => {}
        other => bail!("cannot recover Broadcast from reservation status {other:?}"),
    }
    store.set_dogecoin_transaction_status_by_raw_hash(
        &graph.transaction.raw_hash,
        OperatorStatus::Broadcast,
    )?;
    store.set_process_withdrawal_status(&batch.solana_signature, OperatorStatus::Broadcast)?;
    for request_index in batch.request_start_index..batch.request_end_index {
        store.set_withdrawal_request_status(request_index, OperatorStatus::Broadcast)?;
    }
    store.set_snapshot_batch_status(&batch.solana_signature, OperatorStatus::Broadcast)?;
    Ok(())
}

fn manager_set_pda(manager_set_index: u32) -> Result<Pubkey> {
    let program = Pubkey::from_str(DELEGATED_MANAGER_SET_PROGRAM_ID)
        .context("parse delegated Manager-set program ID")?;
    Ok(Pubkey::find_program_address(
        &[
            b"manager_set",
            &DOGECOIN_CHAIN_ID.to_be_bytes(),
            &manager_set_index.to_be_bytes(),
        ],
        &program,
    )
    .0)
}

fn history_range(history: &[IndexedRequest], start: u64, end: u64) -> Result<Vec<IndexedRequest>> {
    let start = usize::try_from(start).context("withdrawal start exceeds usize")?;
    let end = usize::try_from(end).context("withdrawal end exceeds usize")?;
    history
        .get(start..end)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("withdrawal history does not cover [{start}, {end})"))
}

fn payload_for_requests(
    requests: &[IndexedRequest],
    manager_set_index: u32,
) -> Result<Utx0UnlockPayload> {
    if requests.is_empty() {
        bail!("cannot snapshot an empty withdrawal batch");
    }
    let outputs = requests
        .iter()
        .map(|request| {
            Ok(Utx0Output {
                amount: request.record.net_amount_sats,
                address_type: UtxoAddressType::from_u32(request.record.address_type)?,
                address: request.record.recipient_address,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Utx0UnlockPayload {
        destination_chain: DOGECOIN_CHAIN_ID,
        delegated_manager_set_index: manager_set_index,
        outputs,
    })
}

fn record_requests(store: &OperatorStore, requests: &[IndexedRequest]) -> Result<()> {
    for request in requests {
        let fee_sats = request
            .record
            .amount_sats
            .checked_sub(request.record.net_amount_sats)
            .ok_or_else(|| anyhow!("request net amount exceeds gross amount"))?;
        let mut stored = WithdrawalRequest {
            request_index: request.index,
            solana_signature: request.record.signature.to_string(),
            solana_slot: request.record.slot,
            block_time: request.record.block_time,
            user_pubkey: request.record.user_pubkey.to_string(),
            gross_amount_sats: request.record.amount_sats,
            fee_amount_sats: fee_sats,
            net_amount_sats: request.record.net_amount_sats,
            address_type: request.record.address_type,
            recipient: request.record.recipient_address,
            status: OperatorStatus::Observed,
        };
        if let Some(existing) = store.withdrawal_request_by_index(request.index)? {
            let mut comparable = existing.clone();
            comparable.status = OperatorStatus::Observed;
            if comparable != stored {
                bail!(
                    "persisted withdrawal request {} differs from reconstructed history",
                    request.index
                );
            }
            stored.status = existing.status;
        }
        store.upsert_withdrawal_request(&stored)?;
    }
    Ok(())
}


fn prepared_from_reservation(
    args: &Args,
    bridge_state: Pubkey,
    payload: &Utx0UnlockPayload,
    manager_set: &ManagerSet,
    reservation: CustodyReservation,
    persisted_unsigned: Option<&[u8]>,
) -> Result<PreparedTransaction> {
    let withdrawal_sats = payload.outputs.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.amount)
            .ok_or_else(|| anyhow!("withdrawal amount overflow"))
    })?;
    let required_sats = withdrawal_sats
        .checked_add(args.fee_sats)
        .ok_or_else(|| anyhow!("required custody amount overflow"))?;
    if reservation.required_amount_sats != required_sats {
        bail!(
            "custody reservation {} requires {} sats, persisted payload requires {required_sats}",
            reservation.reservation_id,
            reservation.required_amount_sats
        );
    }
    let selected_sats = reservation.selected_amount_sats;
    let plan = plan_custody_transaction(
        selected_sats,
        withdrawal_sats,
        args.fee_sats,
        args.dust_threshold_sats,
    )?;
    let emitter = bridge_state.to_bytes();
    let selected_inputs = reservation
        .utxos
        .iter()
        .map(|utxo| {
            let redeem_script = build_redeem_script(
                SOLANA_EMITTER_CHAIN,
                &emitter,
                &utxo.original_recipient_address,
                manager_set.m,
                &manager_set.pubkeys,
            )?;
            let script_hash = hash160(&redeem_script);
            let expected_address = args.doge_network.encode_address(1, script_hash)?;
            if expected_address != utxo.custody_address {
                bail!(
                    "custody UTXO {}:{} does not match its redeem script",
                    hex::encode(utxo.txid),
                    utxo.vout
                );
            }
            if !utxo.script_pubkey_hex.is_empty()
                && !utxo
                    .script_pubkey_hex
                    .eq_ignore_ascii_case(&hex::encode(p2sh_script_pubkey(&script_hash)))
            {
                bail!(
                    "custody UTXO {}:{} scriptPubKey mismatch",
                    hex::encode(utxo.txid),
                    utxo.vout
                );
            }
            let mut transaction_id = utxo.txid;
            transaction_id.reverse();
            Ok(SelectedUtxo {
                transaction_id,
                vout: utxo.vout,
                redeem_script,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut transaction_outputs = payload
        .outputs
        .iter()
        .map(|output| TransactionOutput {
            amount: output.amount,
            address_type: output.address_type,
            address: output.address,
        })
        .collect::<Vec<_>>();
    let change_script_hash = if plan.change_sats == 0 {
        None
    } else {
        let redeem_script = build_redeem_script(
            SOLANA_EMITTER_CHAIN,
            &emitter,
            &[0; 32],
            manager_set.m,
            &manager_set.pubkeys,
        )?;
        let script_hash = hash160(&redeem_script);
        transaction_outputs.push(TransactionOutput {
            amount: plan.change_sats,
            address_type: UtxoAddressType::P2sh,
            address: script_hash,
        });
        Some(script_hash)
    };
    let transaction = if let Some(bytes) = persisted_unsigned {
        let recovered = UnsignedTransaction::from_persisted_bytes(bytes, selected_inputs)?;
        if recovered.outputs() != transaction_outputs {
            bail!("persisted unsigned transaction outputs differ from payload and reservation");
        }
        recovered
    } else {
        UnsignedTransaction::new(selected_inputs, transaction_outputs)?
    };
    let unsigned_bytes = transaction.serialize();
    if persisted_unsigned.is_some_and(|bytes| bytes != unsigned_bytes) {
        bail!("persisted unsigned transaction bytes drifted during deterministic recovery");
    }
    Ok(PreparedTransaction {
        transaction,
        unsigned_bytes,
        selected_utxos: reservation.utxos,
        selected_sats,
        plan,
        change_script_hash,
        reservation_id: reservation.reservation_id,
    })
}

async fn register_unsigned_transaction(
    client: &HttpClient,
    manager_url: &str,
    emitter: Pubkey,
    sequence: u64,
    payload: &[u8],
    prepared: &PreparedTransaction,
) -> Result<()> {
    let request = RegisterWithdrawalRequest {
        emitter_chain: SOLANA_EMITTER_CHAIN,
        emitter_address_hex: hex::encode(emitter.to_bytes()),
        sequence,
        payload_hex: hex::encode(payload),
        unsigned_transaction_hex: hex::encode(&prepared.unsigned_bytes),
        inputs: prepared
            .selected_utxos
            .iter()
            .map(|utxo| {
                let mut transaction_id = utxo.txid;
                transaction_id.reverse();
                SigningInput {
                    original_recipient_address_hex: hex::encode(utxo.original_recipient_address),
                    transaction_id_hex: hex::encode(transaction_id),
                    vout: utxo.vout,
                }
            })
            .collect(),
        outputs: prepared
            .transaction
            .outputs()
            .iter()
            .map(|output| SigningOutput {
                amount: output.amount,
                address_type: output.address_type as u32,
                address_hex: hex::encode(output.address),
            })
            .collect(),
    };
    let url = format!("{}/api/v1/withdrawals", manager_url.trim_end_matches('/'));
    let response = client.post(&url).json(&request).send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("Manager signing registration returned {status}: {body}");
    }
    let registered: RegisterWithdrawalResponse = serde_json::from_str(&body)?;
    if registered.sequence != sequence {
        bail!(
            "Manager registered sequence {}, expected {sequence}",
            registered.sequence
        );
    }
    Ok(())
}

fn assert_vaa_and_manager(
    signed_vaa: &[u8],
    signatures: &ManagerSignatures,
    emitter: Pubkey,
    sequence: u64,
    payload: &Utx0UnlockPayload,
    manager_set: &ManagerSet,
) -> Result<()> {
    if !vaa_hash_matches(signed_vaa, &signatures.vaa_hash)? {
        bail!("Manager vaaHash does not match the signed VAA digest");
    }
    let vaa = parse_vaa(signed_vaa)?;
    if vaa.emitter_chain != SOLANA_EMITTER_CHAIN
        || vaa.emitter_address != emitter.to_bytes()
        || vaa.sequence != sequence
        || Utx0UnlockPayload::parse(&vaa.payload)? != *payload
    {
        bail!("signed VAA identity or UTX0 payload mismatch");
    }
    if signatures.destination_chain != DOGECOIN_CHAIN_ID
        || signatures.manager_set_index != payload.delegated_manager_set_index
        || signatures.required != manager_set.m as u32
        || signatures.total != manager_set.n as u32
    {
        bail!("Manager response metadata does not match the VAA and Manager set");
    }
    Ok(())
}

fn apply_manager_signatures(
    transaction: &mut UnsignedTransaction,
    signatures: &ManagerSignatures,
    manager_set: &ManagerSet,
) -> Result<()> {
    let sighashes = (0..transaction.input_count())
        .map(|index| transaction.sighash_all(index))
        .collect::<Result<Vec<_>>>()?;
    let mut seen = HashSet::new();
    let mut per_input = vec![Vec::<(u8, Vec<u8>)>::new(); transaction.input_count()];
    for signer in &signatures.signatures {
        if !seen.insert(signer.signer_index) {
            bail!("duplicate Manager signer {}", signer.signer_index);
        }
        let public_key = manager_set
            .pubkeys
            .get(signer.signer_index as usize)
            .ok_or_else(|| anyhow!("Manager signer index out of range"))?;
        if signer.input_signatures.len() != transaction.input_count() {
            bail!(
                "Manager signer {} returned the wrong input-signature count",
                signer.signer_index
            );
        }
        for (index, signature) in signer.input_signatures.iter().enumerate() {
            if !verify_manager_signature(public_key, &sighashes[index], signature)? {
                bail!("invalid Manager signature for input {index}");
            }
            per_input[index].push((signer.signer_index, signature.clone()));
        }
    }
    for (index, signatures) in per_input.iter_mut().enumerate() {
        signatures.sort_by_key(|(signer, _)| *signer);
        if signatures.len() < manager_set.m as usize {
            bail!(
                "input {index} has {} valid signatures, need {}",
                signatures.len(),
                manager_set.m
            );
        }
        let selected = signatures
            .iter()
            .take(manager_set.m as usize)
            .map(|(_, signature)| signature.clone())
            .collect::<Vec<_>>();
        transaction.apply_script_sig(index, &selected)?;
    }
    Ok(())
}

async fn wait_for_manager_signatures(
    client: &HttpClient,
    manager_url: &str,
    emitter: &[u8; 32],
    sequence: u64,
    interval: Duration,
    timeout: Duration,
) -> Result<ManagerSignatures> {
    let started = Instant::now();
    let mut last_error = None;
    loop {
        match fetch_manager_signatures(client, manager_url, SOLANA_EMITTER_CHAIN, emitter, sequence)
            .await
        {
            Ok(response) if response.is_complete => return Ok(response),
            Ok(response) => {
                last_error = Some(format!(
                    "incomplete with {} signers",
                    response.signatures.len()
                ))
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        if started.elapsed() >= timeout {
            bail!(
                "timed out waiting for Manager signatures: {}",
                last_error.unwrap_or_else(|| "no response".into())
            );
        }
        sleep(interval).await;
    }
}

async fn broadcast_electrs(client: &HttpClient, electrs_url: &str, raw: &[u8]) -> Result<String> {
    let url = format!("{}/tx", electrs_url.trim_end_matches('/'));
    let response = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(hex::encode(raw))
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("electrs broadcast returned {status}: {body}");
    }
    Ok(body.trim().trim_matches('"').to_owned())
}
async fn broadcast_electrs_idempotent(
    client: &HttpClient,
    electrs_url: &str,
    raw: &[u8],
    display_txid: &str,
) -> Result<()> {
    if electrs_has_transaction(client, electrs_url, display_txid).await? {
        return Ok(());
    }
    match broadcast_electrs(client, electrs_url, raw).await {
        Ok(returned) if returned.eq_ignore_ascii_case(display_txid) => Ok(()),
        Ok(returned) => bail!(
            "electrs returned txid {returned}, locally assembled txid is {display_txid}"
        ),
        Err(error) => {
            if electrs_has_transaction(client, electrs_url, display_txid).await? {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

async fn electrs_has_transaction(
    client: &HttpClient,
    electrs_url: &str,
    display_txid: &str,
) -> Result<bool> {
    #[derive(Deserialize)]
    struct ElectrsTransaction {
        txid: String,
    }

    let url = format!("{}/tx/{display_txid}", electrs_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    let status = response.status();
    let body = response.text().await.with_context(|| format!("read {url}"))?;
    if !status.is_success() {
        bail!("Electrs GET {url} returned {status}: {body}");
    }
    let transaction: ElectrsTransaction =
        serde_json::from_str(&body).with_context(|| format!("decode Electrs response from {url}"))?;
    if !transaction.txid.eq_ignore_ascii_case(display_txid) {
        bail!(
            "Electrs GET returned txid {}, expected {display_txid}",
            transaction.txid
        );
    }
    Ok(true)
}


async fn read_bridge_state(
    rpc: &RpcClient,
    bridge_state: Pubkey,
    owner: Pubkey,
) -> Result<doge_bridge_client::PsyBridgeProgramState> {
    let account = rpc.get_account(&bridge_state).await?;
    if account.owner != owner {
        bail!("bridge state owner mismatch");
    }
    let state: &psy_doge_solana_core::program_state::BridgeProgramStateWithDogeMint =
        bytemuck::try_from_bytes(&account.data)
            .map_err(|error| anyhow!("decode bridge state: {error}"))?;
    Ok(state.core_state.clone())
}

async fn load_indexed_requests(args: &Args, bridge_state: Pubkey) -> Result<Vec<IndexedRequest>> {
    let config = HistorySyncConfig::new(
        args.solana_rpc_url().to_owned(),
        args.doge_bridge_program,
        bridge_state,
        args.pending_mint_program,
        args.txo_buffer_program,
    )
    .include_withdrawals(true)
    .include_manual_deposits(false);
    let sync = BridgeHistorySync::new(config)?;
    let (mut receiver, mut handle) = sync.stream_history(None).await?;
    let mut requests = Vec::new();
    while let Some(record) = receiver.recv().await {
        if let HistoryRecord::WithdrawalRequest(record) = record {
            requests.push(record);
        }
    }
    handle.join().await?;
    Ok(requests
        .into_iter()
        .enumerate()
        .map(|(index, record)| IndexedRequest {
            index: index as u64,
            record,
        })
        .collect())
}

async fn create_generic_buffer(
    rpc: &RpcClient,
    payer: &Keypair,
    writer: &Keypair,
    program_id: Pubkey,
    data: &[u8],
) -> Result<Pubkey> {
    let target_size = u32::try_from(data.len()).context("generic-buffer payload exceeds u32")?;
    let account = Keypair::new();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(GENERIC_BUFFER_HEADER_SIZE)
        .await?;
    let create = system_instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        rent,
        GENERIC_BUFFER_HEADER_SIZE as u64,
        &program_id,
    );
    let init = instructions::generic_buffer_init(
        program_id,
        account.pubkey(),
        writer.pubkey(),
        target_size,
    );
    send_solana_transaction_with_signers(rpc, payer, &[create, init], &[&account, writer]).await?;
    for (index, chunk) in data.chunks(GENERIC_BUFFER_CHUNK_SIZE).enumerate() {
        let offset = u32::try_from(index * GENERIC_BUFFER_CHUNK_SIZE)?;
        let write = instructions::generic_buffer_write(
            program_id,
            account.pubkey(),
            writer.pubkey(),
            offset,
            chunk,
        );
        send_solana_transaction_with_signers(rpc, payer, &[write], &[writer]).await?;
    }
    Ok(account.pubkey())
}

async fn verify_generic_buffer(
    rpc: &RpcClient,
    address: Pubkey,
    owner: Pubkey,
    writer: Pubkey,
    payload: &[u8],
) -> Result<()> {
    let account = rpc.get_account(&address).await?;
    if account.owner != owner
        || account.data.len() != GENERIC_BUFFER_HEADER_SIZE + payload.len()
        || account.data[..GENERIC_BUFFER_HEADER_SIZE] != writer.to_bytes()
        || account.data[GENERIC_BUFFER_HEADER_SIZE..] != *payload
    {
        bail!("generic buffer does not contain the exact UTX0 payload");
    }
    Ok(())
}

async fn ensure_fee_collector_funding(
    rpc: &RpcClient,
    payer: &Keypair,
    fee_collector: Pubkey,
) -> Result<()> {
    let minimum = rpc.get_minimum_balance_for_rent_exemption(0).await?;
    let balance = rpc.get_balance(&fee_collector).await?;
    if balance >= minimum {
        return Ok(());
    }
    let transfer = system_instruction::transfer(&payer.pubkey(), &fee_collector, minimum - balance);
    send_solana_transaction(rpc, payer, &[transfer]).await?;
    Ok(())
}

async fn ensure_operator_fee_funding(
    rpc: &RpcClient,
    payer: &Keypair,
    operator: &Keypair,
) -> Result<()> {
    let balance = rpc.get_balance(&operator.pubkey()).await?;
    let required = rpc
        .get_minimum_balance_for_rent_exemption(0)
        .await?
        .checked_add(WORMHOLE_FEE_PREPAY_LAMPORTS)
        .ok_or_else(|| anyhow!("operator fee-funding requirement overflow"))?;
    if balance >= required {
        return Ok(());
    }
    if payer.pubkey() == operator.pubkey() {
        bail!(
            "operator requires {} more lamports to post the snapshot VAA",
            required - balance
        );
    }
    let transfer =
        system_instruction::transfer(&payer.pubkey(), &operator.pubkey(), required - balance);
    send_solana_transaction(rpc, payer, &[transfer]).await?;
    Ok(())
}

async fn read_wormhole_sequence(
    rpc: &RpcClient,
    emitter: Pubkey,
    wormhole_core_program: Pubkey,
) -> Result<Option<u64>> {
    let (sequence, _) =
        Pubkey::find_program_address(&[b"Sequence", emitter.as_ref()], &wormhole_core_program);
    let Some(account) = rpc
        .get_account_with_commitment(&sequence, rpc.commitment())
        .await?
        .value
    else {
        return Ok(None);
    };
    if account.owner != wormhole_core_program || account.data.len() != 8 {
        bail!("invalid Wormhole sequence account {sequence}");
    }
    Ok(Some(u64::from_le_bytes(
        account.data[..8].try_into().unwrap(),
    )))
}

fn signed_solana_transaction(
    payer: &Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
    extra_signers: &[&Keypair],
    blockhash: solana_sdk::hash::Hash,
) -> Transaction {
    let mut signers = vec![payer];
    for signer in extra_signers {
        if signer.pubkey() != payer.pubkey() {
            signers.push(*signer);
        }
    }
    Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &signers,
        blockhash,
    )
}

async fn send_solana_transaction(
    rpc: &RpcClient,
    payer: &Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
) -> Result<Signature> {
    send_solana_transaction_with_signers(rpc, payer, instructions, &[]).await
}

async fn send_solana_transaction_with_signers(
    rpc: &RpcClient,
    payer: &Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
    extra_signers: &[&Keypair],
) -> Result<Signature> {
    let blockhash = rpc.get_latest_blockhash().await?;
    let mut signers = vec![payer];
    for signer in extra_signers {
        if signer.pubkey() != payer.pubkey() {
            signers.push(*signer);
        }
    }
    let transaction = Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &signers,
        blockhash,
    );
    rpc.send_and_confirm_transaction(&transaction)
        .await
        .map_err(Into::into)
}

async fn wait_for_transaction_meta(
    rpc: &RpcClient,
    signature: &Signature,
    timeout: Duration,
) -> Result<solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta> {
    let started = Instant::now();
    loop {
        if let Ok(transaction) = rpc
            .get_transaction(signature, UiTransactionEncoding::Base64)
            .await
        {
            return Ok(transaction);
        }
        if started.elapsed() >= timeout {
            bail!("transaction {signature} metadata was not readable before timeout");
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn find_noop_message(
    args: &Args,
    bridge_state: Pubkey,
    signature: &Signature,
) -> Result<doge_bridge_client::NoopShimWithdrawalMessage> {
    let program = args.wormhole_shim_program();
    {
        let monitor = NoopShimMonitor::new(
            NoopShimMonitorConfig::new(args.solana_rpc_url().to_owned(), bridge_state)
                .noop_shim_program_id(program)
                .batch_size(50),
        )?;
        let mut before = None;
        for _ in 0..10 {
            let page = monitor.get_withdrawals(before, 50).await?;
            if let Some(message) = page
                .messages
                .into_iter()
                .find(|message| message.signature == *signature)
            {
                return Ok(message);
            }
            if !page.has_more {
                break;
            }
            before = page.next_cursor;
        }
    }
    bail!("snapshot signature {signature} not found in Wormhole shim history")
}

fn hash160(bytes: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(bytes)).into()
}

fn hash_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn read_keypair(path: &Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|error| anyhow!("read {role} keypair {}: {error}", path.display()))
}

fn write_evidence(path: &Path, evidence: &Evidence) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(evidence)?;
    std::fs::write(path, &bytes).with_context(|| format!("write {}", path.display()))?;
    println!("{}", String::from_utf8(bytes).expect("JSON is UTF-8"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(index: u64, recipient: u8, amount: u64) -> IndexedRequest {
        IndexedRequest {
            index,
            record: WithdrawalRequestRecord {
                signature: Signature::new_unique(),
                slot: index + 1,
                block_time: None,
                amount_sats: amount + 1_000,
                net_amount_sats: amount,
                recipient_address: [recipient; 20],
                address_type: 0,
                user_pubkey: Pubkey::new_unique(),
            },
        }
    }

    #[test]
    fn snapshot_payload_covers_full_cursor_interval() {
        let requests = vec![request(3, 0x11, 5), request(4, 0x22, 7)];
        let payload = payload_for_requests(&requests, 9).unwrap();
        assert_eq!(payload.delegated_manager_set_index, 9);
        assert_eq!(payload.outputs.len(), 2);
        assert_eq!(payload.outputs[0].amount, 5);
        assert_eq!(payload.outputs[0].address, [0x11; 20]);
        assert_eq!(payload.outputs[1].amount, 7);
    }

    #[test]
    fn history_range_requires_complete_batch() {
        let requests = vec![request(0, 0x11, 5), request(1, 0x22, 7)];
        assert_eq!(history_range(&requests, 0, 2).unwrap().len(), 2);
        assert!(history_range(&requests, 1, 3).is_err());
    }

    #[test]
    fn recording_reconstructed_requests_preserves_forward_status() {
        let store = OperatorStore::open_in_memory().unwrap();
        let request = request(7, 0x44, 25_000);
        record_requests(&store, std::slice::from_ref(&request)).unwrap();
        store
            .set_withdrawal_request_status(7, OperatorStatus::Broadcast)
            .unwrap();
        record_requests(&store, std::slice::from_ref(&request)).unwrap();
        assert_eq!(
            store.withdrawal_request_by_index(7).unwrap().unwrap().status,
            OperatorStatus::Broadcast
        );
    }

    #[test]
    fn p0_3_snapshot_batch_is_capped_at_319() {
        assert_eq!(capped_batch_end(0, 320), 319);
        assert_eq!(capped_batch_end(9, 10), 10);
        assert_eq!(capped_batch_end(u64::MAX - 2, u64::MAX), u64::MAX);
    }

    #[test]
    fn observed_batch_action_never_changes_blockhash_on_ambiguous_status() {
        assert_eq!(
            select_observed_batch_action(None, false, false, 4, 3),
            ObservedBatchAction::Wait
        );
        assert_eq!(
            select_observed_batch_action(None, false, true, 3, 3),
            ObservedBatchAction::ResendOriginal
        );
        assert_eq!(
            select_observed_batch_action(Some(false), false, false, 3, 3),
            ObservedBatchAction::Fail
        );
        assert_eq!(
            select_observed_batch_action(Some(true), false, false, 3, 3),
            ObservedBatchAction::AwaitConfirmation
        );
        assert_eq!(
            select_observed_batch_action(Some(false), true, false, 3, 3),
            ObservedBatchAction::Fail
        );
    }

    fn custody_utxo(seed: u8, amount_sats: u64, key_reference: &str) -> CustodyUtxo {
        CustodyUtxo {
            txid: [seed; 32],
            vout: 0,
            amount_sats,
            script_pubkey_hex: hex::encode(p2sh_script_pubkey(&[seed; 20])),
            custody_address: DogeNetwork::Regtest
                .encode_address(1, [seed; 20])
                .unwrap(),
            key_reference: key_reference.to_owned(),
            confirmation_block_hash: Some([seed.wrapping_add(1); 32]),
            confirmation_height: Some(10),
            confirmations: 6,
            leaf_index: u64::from(seed),
            status: CustodyUtxoStatus::Available,
            reservation_id: None,
            spend_txid: None,
            source_deposit_txid: Some([seed; 32]),
            source_solana_signature: None,
            spend_request_index: None,
            spend_process_signature: None,
            original_recipient_address: [seed; 32],
        }
    }

    fn observed_batch(signature: &str, reservation_id: &str) -> SnapshotBatch {
        SnapshotBatch {
            solana_signature: signature.to_owned(),
            solana_slot: 0,
            block_time: None,
            request_start_index: 0,
            request_end_index: 1,
            snapshot_root: [7; 32],
            payload: vec![1, 2, 3],
            payload_hash: hash_sha256(&[1, 2, 3]),
            wormhole_sequence: 4,
            solana_transaction: Some(vec![5]),
            unsigned_transaction: Some(vec![6]),
            reservation_id: Some(reservation_id.to_owned()),
            status: OperatorStatus::Observed,
        }
    }

    #[test]
    fn atomic_observed_failure_leaves_no_reserved_utxo() {
        let mut store = OperatorStore::open_in_memory().unwrap();
        store
            .upsert_custody_utxo(&custody_utxo(1, 20_000, "key-1"))
            .unwrap();
        let error = store
            .reserve_custody_for_snapshot("res", 10_000, |_reservation| {
                Err(doge_bridge_client::operator_store::OperatorStoreError::InvalidTransition(
                    "fixture failure".to_owned(),
                ))
            })
            .unwrap_err();
        assert!(error.to_string().contains("fixture failure"));
        assert!(store.load_reservation("res").unwrap().is_none());
        assert_eq!(
            store
                .custody_utxo_by_outpoint(&[1; 32], 0)
                .unwrap()
                .unwrap()
                .status,
            CustodyUtxoStatus::Available
        );
    }

    #[test]
    fn observed_fail_releases_while_wait_preserves_reservation() {
        let mut store = OperatorStore::open_in_memory().unwrap();
        store
            .upsert_custody_utxo(&custody_utxo(2, 20_000, "key-1"))
            .unwrap();
        let batch = observed_batch("snap-fail", "res-fail");
        store
            .reserve_custody_for_snapshot("res-fail", 10_000, |_reservation| Ok(batch.clone()))
            .unwrap();
        assert!(apply_observed_terminal_effect(
            &mut store,
            &batch,
            ObservedBatchAction::Wait
        )
        .is_err());
        assert_eq!(
            store.load_reservation("res-fail").unwrap().unwrap().status,
            CustodyReservationStatus::Reserved
        );
        assert!(apply_observed_terminal_effect(
            &mut store,
            &batch,
            ObservedBatchAction::Fail
        )
        .is_err());
        assert_eq!(
            store.load_reservation("res-fail").unwrap().unwrap().status,
            CustodyReservationStatus::Released
        );
        assert_eq!(
            store
                .snapshot_batch_by_signature("snap-fail")
                .unwrap()
                .unwrap()
                .status,
            OperatorStatus::Failed
        );
    }

    #[test]
    fn observed_resend_effect_does_not_mutate_store() {
        let mut store = OperatorStore::open_in_memory().unwrap();
        store
            .upsert_custody_utxo(&custody_utxo(3, 20_000, "key-1"))
            .unwrap();
        let batch = observed_batch("snap-resend", "res-resend");
        store
            .reserve_custody_for_snapshot("res-resend", 10_000, |_reservation| Ok(batch.clone()))
            .unwrap();
        apply_observed_terminal_effect(&mut store, &batch, ObservedBatchAction::ResendOriginal)
            .unwrap();
        assert_eq!(
            store
                .snapshot_batch_by_signature("snap-resend")
                .unwrap()
                .unwrap()
                .status,
            OperatorStatus::Observed
        );
        assert_eq!(
            store.load_reservation("res-resend").unwrap().unwrap().status,
            CustodyReservationStatus::Reserved
        );
    }

    #[test]
    fn broadcast_unconfirmed_stays_pending() {
        let transaction = ElectrsWithdrawalTransaction {
            txid: "aa".repeat(32),
            vout: Vec::new(),
            status: ElectrsWithdrawalStatus {
                confirmed: false,
                block_height: None,
                block_hash: None,
            },
        };
        assert!(plan_confirmed_withdrawal(transaction, &"aa".repeat(32), &[], 100)
            .unwrap()
            .is_none());
    }

    #[test]
    fn confirmed_position_and_change_are_derived_from_electrs() {
        let display_txid = "11".repeat(32);
        let block_hash = "22".repeat(32);
        let script_hash = [0x33; 20];
        let unsigned = UnsignedTransaction::new(
            vec![SelectedUtxo {
                transaction_id: [9; 32],
                vout: 0,
                redeem_script: vec![0x51],
            }],
            vec![
                TransactionOutput {
                    amount: 10_000,
                    address_type: UtxoAddressType::P2pkh,
                    address: [0x44; 20],
                },
                TransactionOutput {
                    amount: 25_000,
                    address_type: UtxoAddressType::P2sh,
                    address: script_hash,
                },
            ],
        )
        .unwrap()
        .serialize();
        let internal_txid = [0x11; 32];
        let input = CustodyUtxo {
            status: CustodyUtxoStatus::Broadcast,
            reservation_id: Some("res-change".to_owned()),
            spend_txid: Some(internal_txid),
            spend_request_index: Some(0),
            spend_process_signature: Some("snap-change".to_owned()),
            ..custody_utxo(9, 50_000, "key-1")
        };
        let reservation = CustodyReservation {
            reservation_id: "res-change".to_owned(),
            required_amount_sats: 35_000,
            selected_amount_sats: 50_000,
            status: CustodyReservationStatus::Broadcast,
            spend_txid: Some(internal_txid),
            request_index: Some(0),
            process_solana_signature: Some("snap-change".to_owned()),
            utxos: vec![input],
        };
        let transaction = DogecoinTransaction {
            raw_hash: [3; 32],
            txid: Some(internal_txid),
            raw_transaction: Some(vec![1]),
            status: OperatorStatus::Broadcast,
            block_hash: None,
            block_height: None,
            confirmations: 0,
        };
        let process = ProcessWithdrawal {
            solana_signature: "snap-change".to_owned(),
            solana_slot: 1,
            block_time: None,
            request_start_index: 0,
            request_end_index: 1,
            snapshot_root: [4; 32],
            dogecoin_raw_hash: transaction.raw_hash,
            return_output_index: 1,
            return_output_amount_sats: 25_000,
            old_spent_txo_root: [0; 32],
            new_spent_txo_root: [0; 32],
            status: OperatorStatus::Broadcast,
        };
        let batch = SnapshotBatch {
            solana_signature: "snap-change".to_owned(),
            solana_slot: 1,
            block_time: None,
            request_start_index: 0,
            request_end_index: 1,
            snapshot_root: process.snapshot_root,
            payload: vec![1],
            payload_hash: hash_sha256(&[1]),
            wormhole_sequence: 1,
            solana_transaction: Some(vec![2]),
            unsigned_transaction: Some(unsigned),
            reservation_id: Some(reservation.reservation_id.clone()),
            status: OperatorStatus::Broadcast,
        };
        let graph = PersistedWithdrawalGraph {
            transaction,
            process,
            reservation,
        };
        let electrs_transaction = ElectrsWithdrawalTransaction {
            txid: display_txid.clone(),
            vout: vec![
                ElectrsWithdrawalOutput {
                    scriptpubkey: hex::encode(crate::wormhole::tx::p2pkh_script_pubkey(&[0x44; 20])),
                    value: 10_000,
                },
                ElectrsWithdrawalOutput {
                    scriptpubkey: hex::encode(p2sh_script_pubkey(&script_hash)),
                    value: 25_000,
                },
            ],
            status: ElectrsWithdrawalStatus {
                confirmed: true,
                block_height: Some(90),
                block_hash: Some(block_hash),
            },
        };
        let confirmed = plan_confirmed_withdrawal(
            electrs_transaction,
            &display_txid,
            &["00".repeat(32), display_txid.clone()],
            100,
        )
        .unwrap()
        .unwrap();
        assert_eq!(confirmed.tx_index, 1);
        assert_eq!(confirmed.confirmations, 11);
        let change = derive_confirmed_change(
            DogeNetwork::Regtest,
            &batch,
            &graph,
            1,
            &confirmed,
        )
        .unwrap()
        .unwrap();
        assert_eq!(change.vout, 1);
        assert_eq!(change.amount_sats, 25_000);
        assert_eq!(
            change.leaf_index,
            custody_ops::compute_combined_index(90, 1, 1)
        );
        assert_eq!(change.original_recipient_address, [0; 32]);
        assert_eq!(change.key_reference, "key-1");
    }

    fn persist_signed_fixture() -> (OperatorStore, SnapshotBatch, [u8; 32]) {
        let mut store = OperatorStore::open_in_memory().unwrap();
        store
            .upsert_custody_utxo(&custody_utxo(0x55, 50_000, "key-1"))
            .unwrap();
        store
            .upsert_withdrawal_request(&WithdrawalRequest {
                request_index: 0,
                solana_signature: "burn-0".to_owned(),
                solana_slot: 1,
                block_time: None,
                user_pubkey: Pubkey::new_unique().to_string(),
                gross_amount_sats: 11_000,
                fee_amount_sats: 1_000,
                net_amount_sats: 10_000,
                address_type: 0,
                recipient: [0x44; 20],
                status: OperatorStatus::Observed,
            })
            .unwrap();
        let mut batch = observed_batch("snap-lifecycle", "res-lifecycle");
        store
            .reserve_custody_for_snapshot("res-lifecycle", 10_000, |_reservation| {
                Ok(batch.clone())
            })
            .unwrap();
        batch.status = OperatorStatus::Constructed;
        store.upsert_snapshot_batch(&batch).unwrap();
        let raw_transaction = vec![1, 2, 3, 4];
        let raw_hash = hash_sha256(&raw_transaction);
        let txid = double_sha256(&raw_transaction);
        store
            .persist_signed_snapshot(
                &batch.solana_signature,
                "res-lifecycle",
                &DogecoinTransaction {
                    raw_hash,
                    txid: Some(txid),
                    raw_transaction: Some(raw_transaction),
                    status: OperatorStatus::Signed,
                    block_hash: None,
                    block_height: None,
                    confirmations: 0,
                },
                &ProcessWithdrawal {
                    solana_signature: batch.solana_signature.clone(),
                    solana_slot: batch.solana_slot,
                    block_time: None,
                    request_start_index: 0,
                    request_end_index: 1,
                    snapshot_root: batch.snapshot_root,
                    dogecoin_raw_hash: raw_hash,
                    return_output_index: 1,
                    return_output_amount_sats: 0,
                    old_spent_txo_root: [0; 32],
                    new_spent_txo_root: [0; 32],
                    status: OperatorStatus::Signed,
                },
            )
            .unwrap();
        batch.status = OperatorStatus::Signed;
        (store, batch, txid)
    }

    #[test]
    fn signed_graph_requires_complete_associations_and_detects_drift() {
        let (store, batch, _) = persist_signed_fixture();
        load_complete_signed_graph(&store, &batch).unwrap();
        store
            .set_withdrawal_request_status(0, OperatorStatus::Constructed)
            .unwrap();
        assert!(load_complete_signed_graph(&store, &batch).is_err());
    }

    #[test]
    fn broadcast_is_incomplete_until_atomic_confirmation() {
        let (mut store, mut batch, txid) = persist_signed_fixture();
        let signed_graph = load_complete_signed_graph(&store, &batch).unwrap();
        complete_broadcast_transition(&mut store, &batch, &signed_graph).unwrap();
        batch.status = OperatorStatus::Broadcast;
        assert_eq!(
            store
                .oldest_incomplete_snapshot_batch()
                .unwrap()
                .unwrap()
                .status,
            OperatorStatus::Broadcast
        );
        let broadcast = store
            .dogecoin_transaction_by_process_signature(&batch.solana_signature)
            .unwrap()
            .unwrap();
        store
            .finalize_confirmed_snapshot(
                &batch.solana_signature,
                &DogecoinTransaction {
                    status: OperatorStatus::Confirmed,
                    block_hash: Some([0x77; 32]),
                    block_height: Some(90),
                    confirmations: 11,
                    ..broadcast
                },
                None,
            )
            .unwrap();
        assert!(store.oldest_incomplete_snapshot_batch().unwrap().is_none());
        assert_eq!(
            store
                .snapshot_batch_by_signature(&batch.solana_signature)
                .unwrap()
                .unwrap()
                .status,
            OperatorStatus::Confirmed
        );
        assert_eq!(
            store
                .load_reservation("res-lifecycle")
                .unwrap()
                .unwrap()
                .status,
            CustodyReservationStatus::Spent
        );
        assert_eq!(
            store
                .custody_utxo_by_outpoint(&[0x55; 32], 0)
                .unwrap()
                .unwrap()
                .status,
            CustodyUtxoStatus::Spent
        );
        assert_eq!(
            store
                .dogecoin_transaction_by_txid(&txid)
                .unwrap()
                .unwrap()
                .status,
            OperatorStatus::Confirmed
        );
    }
}
