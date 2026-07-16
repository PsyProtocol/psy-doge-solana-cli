use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use doge_bridge_client::operator_store::{
    CustodyUtxo, CustodyUtxoStatus, DogecoinTransaction, OperatorStatus, OperatorStore,
    ProcessWithdrawal, WithdrawalRequest,
};
use doge_bridge_client::{
    instructions, BridgeApi, BridgeClient, BridgeClientConfigBuilder, BridgeHistorySync,
    HistoryRecord, HistorySyncConfig, NoopShimMonitor, NoopShimMonitorConfig, OperatorApi,
    WithdrawalRequestRecord,
};
use doge_local_ops::wormhole::{
    manager::{
        fetch_manager_signatures, fetch_signed_vaa, local_regtest_manager_set, parse_vaa,
        vaa_hash_matches, vaa_signing_digest, verify_manager_signature, ManagerSet,
        ManagerSignatures,
    },
    redeem::build_redeem_script,
    tx::{double_sha256, p2sh_script_pubkey, UnsignedTransaction},
    utx0::{Utx0Input, Utx0Output, Utx0UnlockPayload, UtxoAddressType},
};
use doge_local_ops::{custody_ops, extract_vout_and_sats, plan_custody_transaction};
use psy_bridge_core::crypto::hash::{
    merkle::fixed_append_tree::FixedMerkleAppendTree, sha256::SHA256_ZERO_HASHES,
    sha256_impl::hash_impl_sha256_bytes,
};
use psy_doge_solana_core::{
    constants::DOGECOIN_CHAIN_ID,
    instructions::doge_bridge::WithdrawalRequestProof,
    program_state::{
        proc_withdrawal::compute_withdrawal_intent_hash, PendingWithdrawal, PsyWithdrawalRequest,
        PENDING_WITHDRAWAL_STATUS_FINALIZED, PENDING_WITHDRAWAL_STATUS_PENDING_VAA,
    },
    utils::fees::calcuate_withdrawal_fee,
};
use reqwest::Client as HttpClient;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
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
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::time::sleep;

const DEFAULT_DOGE_BRIDGE: &str = "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ";
const DEFAULT_PENDING_MINT: &str = "PMUSqycT1j5JTLmHk8frGSCido2h9VG1pyh2MPEa33o";
const DEFAULT_TXO_BUFFER: &str = "TXWhjswto9q6hfaGPuAhDS79wAHKfbMJLVR178xYAaQ";
const DEFAULT_GENERIC_BUFFER: &str = "GBYLmevzPSBPWfWrJ1h9gNzHqUjDXETzHKL1AasLyKwC";
const DEFAULT_MANUAL_CLAIM: &str = "MCdYbqiK3uj36tohbMjsh3Ssg8iRSJmSHToNxW8TWWE";
const DEFAULT_NOOP_SHIM: &str = "FwDChsHWLwbhTiYQ4Sum5mjVWswECi9cmrA11GUFUuxi";
const GENERIC_BUFFER_HEADER_SIZE: usize = 32;
const SOLANA_TRANSACTION_SIZE_LIMIT: usize = 1_232;
// Serialized legacy transaction overhead for generic_buffer_write with a
// separate payer and writer: two signatures, five account keys, blockhash,
// and instruction framing.
const GENERIC_BUFFER_WRITE_TRANSACTION_OVERHEAD: usize = 338;
const GENERIC_BUFFER_WRITE_TRANSACTION_SAFETY_MARGIN: usize = 16;
const GENERIC_BUFFER_CHUNK_SIZE: usize = SOLANA_TRANSACTION_SIZE_LIMIT
    - GENERIC_BUFFER_WRITE_TRANSACTION_OVERHEAD
    - GENERIC_BUFFER_WRITE_TRANSACTION_SAFETY_MARGIN;
const AUTHORIZE_COMPUTE_UNITS: u32 = 1_400_000;
const WORMHOLE_FEE_PREPAY_LAMPORTS: u64 = 1_000;
const DUST_THRESHOLD_SATS: u64 = 10_000;
const SOLANA_EMITTER_CHAIN: u16 = 1;

/// Delegated Manager Set program on Solana (Solana mirror of EVM
/// DelegatedManagerSet). Used to derive the manager-set PDA for
/// authorize_withdrawal.
const DELEGATED_MANAGER_SET_PROGRAM_ID: &str = "wdmsTJP6YnsfeQjPuuEzGCrHmZvTmNy8VkxMCK8JkBX";

#[derive(Debug, Parser)]
#[command(
    name = "process-withdrawal",
    about = "Authorize, relay, confirm, and finalize a Dogecoin withdrawal through the output-only bridge",
    long_about = "Loads an authoritative Solana withdrawal request, selects custody UTXOs, constructs the UTX0 payload, authorizes it atomically on-chain with request membership and output checks plus Wormhole VAA emission, obtains local manager signatures, broadcasts the signed Dogecoin transaction through electrs, waits for confirmation, and finalizes the bridge state.",
    after_long_help = "The local manager service must be running (local_manager_service --listen 127.0.0.1:7071). Manager set index 0 is the deterministic local-regtest 5-of-7 fixture."
)]
struct Args {
    #[arg(
        long,
        conflicts_with = "request_signature",
        required_unless_present = "request_signature"
    )]
    request_index: Option<u64>,
    #[arg(
        long,
        conflicts_with = "request_index",
        required_unless_present = "request_index"
    )]
    request_signature: Option<Signature>,
    #[arg(long, default_value_t = 1_000_000)]
    fee_sats: u64,
    #[arg(long, default_value_t = DUST_THRESHOLD_SATS)]
    dust_threshold_sats: u64,
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    solana_rpc_url: String,
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
    #[arg(long, default_value = DEFAULT_MANUAL_CLAIM)]
    manual_claim_program: Pubkey,
    #[arg(long, default_value = DEFAULT_NOOP_SHIM)]
    noop_shim_program: Pubkey,
    #[arg(long, default_value = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5")]
    wormhole_core_program: Pubkey,
    #[arg(long, default_value = "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX")]
    wormhole_shim_program: Pubkey,
    #[arg(long)]
    bridge_state: Option<Pubkey>,
    #[arg(long, default_value = "http://127.0.0.1:22555")]
    doge_rpc_url: String,
    #[arg(long, default_value = "doge")]
    doge_rpc_user: String,
    #[arg(long, default_value = "doge")]
    doge_rpc_password: String,
    #[arg(long, default_value = "http://127.0.0.1:7071")]
    manager_service_url: String,
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    electrs_url: String,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    mine_blocks: u32,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    min_confirmations: u32,
    #[arg(long, default_value_t = 120)]
    confirmation_timeout_secs: u64,
    #[arg(long, default_value_t = 500)]
    poll_interval_ms: u64,
    #[arg(long)]
    operator_store: PathBuf,
    #[arg(long, default_value = "/tmp/doge-process-withdrawal-evidence.json")]
    evidence_path: PathBuf,
    #[arg(long, default_value_t = 0)]
    manager_set_index: u32,

    /// Enable live Manager signing. When `false` (the default, dry-run mode)
    /// the relay does NOT register the withdrawal with the local Manager
    /// service (so no new signatures are produced) and performs a single
    /// Manager API fetch of whatever signatures already exist, verifying them
    /// locally per input SIGHASH_ALL. Set `true` for the full live flow.
    #[arg(long, default_value_t = false)]
    manager_signing_enabled: bool,

    /// Enable electrs broadcast. When `false` (the default, dry-run mode) the
    /// assembled signed Dogecoin transaction is recorded and printed but never
    /// sent to electrs, and the confirmation (Stage 4) and finalization
    /// (Stage 5) stages are skipped. Set `true` to broadcast and finalize.
    #[arg(long, default_value_t = false)]
    broadcast_enabled: bool,
}

#[derive(Clone, Debug)]
struct IndexedRequest {
    index: u64,
    record: WithdrawalRequestRecord,
}

struct DogeRpc {
    client: HttpClient,
    url: String,
    user: String,
    password: String,
}

impl DogeRpc {
    fn new(url: String, user: String, password: String) -> Self {
        Self {
            client: HttpClient::new(),
            url,
            user,
            password,
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let response = self
            .client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "doge-local-withdrawal",
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .with_context(|| format!("call Dogecoin RPC {method}"))?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .with_context(|| format!("decode Dogecoin RPC {method} (HTTP {status})"))?;
        if !status.is_success() {
            bail!("Dogecoin RPC {method} returned HTTP {status}: {body}");
        }
        if let Some(error) = body.get("error").filter(|value| !value.is_null()) {
            bail!("Dogecoin RPC {method} error: {error}");
        }
        body.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("Dogecoin RPC {method} missing result"))
    }
}

#[derive(Debug)]
struct PreparedTransaction {
    utx0: Utx0UnlockPayload,
    utx0_bytes: Vec<u8>,
    unsigned_tx_bytes: Vec<u8>,
    utx0_hash: [u8; 32],
    unsigned_tx_hash: [u8; 32],
    change_script_hash: Option<[u8; 20]>,
    change_address: Option<String>,
}

#[derive(Debug)]
struct RelayedTransaction {
    raw_bytes: Vec<u8>,
    raw_hash: [u8; 32],
    final_txid: [u8; 32],
    txid_text: String,
    evidence: RelayEvidence,
}

#[derive(Debug)]
struct RelayEvidence {
    vaa_hash: [u8; 32],
    signed_vaa_sha256: [u8; 32],
    signed_vaa_bytes: usize,
    signature_count: usize,
    required: u32,
    total: u32,
    signer_indices: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterWithdrawalRequest {
    emitter_chain: u16,
    emitter_address_hex: String,
    sequence: u64,
    payload_hex: String,
}

#[derive(Debug, Deserialize)]
struct RegisterWithdrawalResponse {
    sequence: u64,
}

#[derive(Serialize)]
struct Evidence {
    schema: String,
    stage: String,
    completed: bool,
    request: Value,
    authorize: Value,
    relay: Value,
    confirmation: Value,
    finalize: Value,
    custody: Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    run(Args::parse()).await
}

async fn run(args: Args) -> Result<()> {
    if args.manager_set_index != 0 {
        bail!(
            "local manager service only supports deterministic manager set index 0, got {}",
            args.manager_set_index
        );
    }

    let bridge_state_pda = Pubkey::find_program_address(
        &[doge_bridge_client::constants::BRIDGE_STATE_SEED],
        &args.doge_bridge_program,
    )
    .0;
    if let Some(provided) = args.bridge_state {
        if provided != bridge_state_pda {
            bail!("--bridge-state mismatch: expected {bridge_state_pda}, got {provided}");
        }
    }

    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;
    let client_config = BridgeClientConfigBuilder::new()
        .rpc_url(args.solana_rpc_url.clone())
        .bridge_state_pda(bridge_state_pda)
        .operator(clone_keypair(&operator)?)
        .payer(clone_keypair(&payer)?)
        .program_id(args.doge_bridge_program)
        .pending_mint_program_id(args.pending_mint_program)
        .txo_buffer_program_id(args.txo_buffer_program)
        .generic_buffer_program_id(args.generic_buffer_program)
        .manual_claim_program_id(args.manual_claim_program)
        .wormhole_core_program_id(args.wormhole_core_program)
        .wormhole_shim_program_id(args.wormhole_shim_program)
        .build()
        .context("build bridge client")?;
    let bridge_client = BridgeClient::with_config(client_config)?;
    let solana_rpc =
        RpcClient::new_with_commitment(args.solana_rpc_url.clone(), CommitmentConfig::confirmed());
    let mut store = OperatorStore::open(&args.operator_store).context("open operator store")?;

    // ── Stage 1: Load and verify ──────────────────────────────────────────

    let history = load_indexed_requests(&args, bridge_state_pda).await?;
    let selected = select_request(
        &history,
        args.request_index,
        args.request_signature.as_ref(),
    )?;
    let pre_snapshot = bridge_client.get_current_bridge_state().await?;
    ensure_next_unprocessed(&selected, pre_snapshot.next_processed_withdrawals_index)?;

    let fee = calcuate_withdrawal_fee(
        selected.record.amount_sats,
        pre_snapshot.config_params.withdrawal_flat_fee_sats,
        pre_snapshot.config_params.withdrawal_fee_rate_numerator,
        pre_snapshot.config_params.withdrawal_fee_rate_denominator,
    )
    .context("calculate withdrawal fee")?;
    if fee.amount_after_fees == 0 {
        bail!("withdrawal amount after fees is zero");
    }
    let recipient_address = dogecoin_regtest_address(
        selected.record.address_type,
        selected.record.recipient_address,
    )?;

    store.upsert_withdrawal_request(&store_request(
        &selected,
        fee.fees_generated,
        fee.amount_after_fees,
        OperatorStatus::Observed,
    ))?;
    let snapshot_signature = bridge_client
        .execute_snapshot_withdrawals()
        .await
        .context("snapshot_withdrawals")?;
    let state = bridge_client
        .get_current_bridge_state()
        .await
        .context("read bridge state after snapshot")?;
    verify_snapshot(&state, &selected)?;
    store.upsert_withdrawal_request(&store_request(
        &selected,
        fee.fees_generated,
        fee.amount_after_fees,
        OperatorStatus::Snapshotted,
    ))?;

    let doge = DogeRpc::new(
        args.doge_rpc_url.clone(),
        args.doge_rpc_user.clone(),
        args.doge_rpc_password.clone(),
    );
    verify_regtest(&doge).await?;

    // Select custody UTXOs — operator chooses which UTXOs to spend.
    // No spent-tree computation: the bridge no longer tracks which custody
    // inputs are spent (output-only authorization model).
    let all_utxos = store.list_custody_utxos().context("list custody UTXOs")?;
    let reservation_id = format!("withdrawal-{}", selected.index);
    let required_sats = fee
        .amount_after_fees
        .checked_add(args.fee_sats)
        .ok_or_else(|| anyhow!("required custody amount overflow"))?;
    let reservation = store
        .reserve_custody_utxos(&reservation_id, required_sats)
        .map_err(|error| anyhow!("custody UTXO reservation failed: {error}"))?;
    let reserved_utxos = reservation.utxos.clone();
    let selected_sats = reserved_utxos.iter().try_fold(0u64, |sum, utxo| {
        sum.checked_add(utxo.amount_sats)
            .ok_or_else(|| anyhow!("selected custody value overflow"))
    })?;
    let plan = plan_custody_transaction(
        selected_sats,
        fee.amount_after_fees,
        args.fee_sats,
        args.dust_threshold_sats,
    )
    .map_err(|error| {
        let _ = store.release_reservation(&reservation_id);
        error
    })?;

    let manager_set = local_regtest_manager_set();
    let prepared = build_prepared_transaction(
        &selected,
        &reserved_utxos,
        &plan,
        bridge_state_pda,
        args.manager_set_index,
        &manager_set,
        &recipient_address,
    )?;

    let request_start = selected.index;
    let request_end = request_start
        .checked_add(1)
        .ok_or_else(|| anyhow!("withdrawal request index overflow"))?;

    // Compute intent_hash per the v3 spec (no spent-tree fields).
    // canonical_manager_set_bytes = MANAGER_SET_PREFIX || compressed_pubkeys,
    // matching the on-chain `manager_set.manager_set` field exactly (234 bytes).
    let canonical_manager_set_bytes = {
        let mut buf = Vec::with_capacity(3 + manager_set.pubkeys.len() * 33);
        buf.push(0x01); // Type tag (on-chain MANAGER_SET_PREFIX[0])
        buf.push(manager_set.m);
        buf.push(manager_set.n);
        for pk in &manager_set.pubkeys {
            buf.extend_from_slice(pk);
        }
        buf
    };
    let intent_hash = compute_withdrawal_intent_hash(
        request_start,
        request_end,
        &canonical_manager_set_bytes,
        &prepared.utx0_hash,
        &prepared.unsigned_tx_hash,
    );

    // Build burn-request Merkle proofs: leaf preimages + 32-level
    // FixedMerkleAppendTree membership paths against the snapshot root.
    let burn_request_proofs =
        build_burn_request_proofs(&history, &state, request_start, request_end)?;
    let burn_request_proof_bytes =
        instructions::serialize_withdrawal_request_proofs(&burn_request_proofs);
    let request_proof_buffer = create_generic_buffer_with_writer(
        &solana_rpc,
        &payer,
        &operator,
        args.generic_buffer_program,
        &burn_request_proof_bytes,
    )
    .await?;
    verify_generic_buffer(
        &solana_rpc,
        request_proof_buffer,
        args.generic_buffer_program,
        operator.pubkey(),
        &burn_request_proof_bytes,
    )
    .await?;

    // ── Stage 2: Authorize ─────────────────────────────────────────────────

    // Create generic buffer with the exact UTX0 payload.
    let utx0_buffer = create_generic_buffer(
        &solana_rpc,
        &payer,
        args.generic_buffer_program,
        &prepared.utx0_bytes,
    )
    .await?;
    verify_generic_buffer(
        &solana_rpc,
        utx0_buffer,
        args.generic_buffer_program,
        payer.pubkey(),
        &prepared.utx0_bytes,
    )
    .await?;

    // Derive the manager-set PDA (DelegatedManagerSet program).
    let delegated_manager_set_program = Pubkey::from_str(DELEGATED_MANAGER_SET_PROGRAM_ID)
        .context("parse DelegatedManagerSet program ID")?;
    let (manager_set_account, _) = Pubkey::find_program_address(
        &[
            b"manager_set",
            &DOGECOIN_CHAIN_ID.to_be_bytes(),
            &args.manager_set_index.to_be_bytes(),
        ],
        &delegated_manager_set_program,
    );

    let authorize_ix = instructions::authorize_withdrawal(
        args.doge_bridge_program,
        operator.pubkey(),
        utx0_buffer,
        request_proof_buffer,
        manager_set_account,
        args.wormhole_shim_program,
        args.wormhole_core_program,
        request_start,
        request_end,
        args.manager_set_index,
        intent_hash,
    );
    let (fee_collector_pda, _) =
        Pubkey::find_program_address(&[b"fee_collector"], &args.wormhole_core_program);
    ensure_operator_authorize_funding(&solana_rpc, &payer, &operator).await?;
    let fee_prepay_ix = system_instruction::transfer(
        &operator.pubkey(),
        &fee_collector_pda,
        WORMHOLE_FEE_PREPAY_LAMPORTS,
    );
    let authorize_signature = send_solana_transaction(
        &solana_rpc,
        &payer,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(AUTHORIZE_COMPUTE_UNITS),
            fee_prepay_ix,
            authorize_ix,
        ],
        &[&operator],
    )
    .await
    .context("submit authorize_withdrawal")?;
    let authorize_meta = solana_rpc
        .get_transaction(&authorize_signature, UiTransactionEncoding::Base64)
        .await
        .context("fetch authorize_withdrawal transaction")?;

    // Verify the bridge state was not mutated by authorization (only the
    // active intent hash and pending PDA should change).
    let post_authorize_state = bridge_client
        .get_current_bridge_state()
        .await
        .context("read bridge state after authorize_withdrawal")?;
    verify_authorize_state_unchanged(&state, &post_authorize_state, intent_hash)?;

    // Verify the VAA was emitted via the pinned Wormhole CPI.
    let noop =
        find_noop_message_for_programs(&args, bridge_state_pda, &authorize_signature).await?;
    if noop.emitter != bridge_state_pda {
        bail!("noop emitter mismatch");
    }
    if noop.payer != operator.pubkey() {
        bail!(
            "noop payer mismatch: expected operator {}, got {}",
            operator.pubkey(),
            noop.payer
        );
    }
    if noop.consistency_level != 1 {
        bail!(
            "noop consistency level is {}, expected 1",
            noop.consistency_level
        );
    }
    if noop.sighash != prepared.utx0_hash {
        bail!("noop UTX0 hash mismatch");
    }
    if noop.doge_tx_bytes != prepared.utx0_bytes {
        bail!("noop shim did not emit the exact prepared UTX0 payload");
    }
    let sequence = noop.nonce as u64;

    // Verify the pending PDA was created with status PENDING_VAA.
    let pending_pda = pending_withdrawal_pda(args.doge_bridge_program, &intent_hash);
    let pending_authorized =
        read_pending_withdrawal(&solana_rpc, pending_pda, args.doge_bridge_program).await?;
    verify_pending_authorized(
        &pending_authorized,
        intent_hash,
        request_start,
        request_end,
        args.manager_set_index,
        prepared.utx0_hash,
        prepared.unsigned_tx_hash,
    )?;
    store.set_withdrawal_request_status(selected.index, OperatorStatus::Constructed)?;

    // ── Stage 3: Relay (dry-run by default) ───────────────────────────────

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build manager/electrs HTTP client")?;
    if args.manager_signing_enabled {
        register_local_withdrawal(
            &http,
            &args.manager_service_url,
            bridge_state_pda,
            sequence,
            &prepared.utx0_bytes,
        )
        .await?;
    } else {
        println!("[dry-run] manager signing skipped (manager_signing_enabled=false); not registering withdrawal with the Manager service");
    }
    let relayed = relay_and_broadcast(
        &http,
        &args.manager_service_url,
        &args.electrs_url,
        bridge_state_pda,
        sequence,
        args.manager_set_index,
        &manager_set,
        &prepared,
        Duration::from_millis(args.poll_interval_ms),
        Duration::from_secs(args.confirmation_timeout_secs),
        args.manager_signing_enabled,
        args.broadcast_enabled,
    )
    .await?;

    store.upsert_dogecoin_transaction(&DogecoinTransaction {
        raw_hash: relayed.raw_hash,
        txid: Some(relayed.final_txid),
        raw_transaction: Some(relayed.raw_bytes.clone()),
        status: OperatorStatus::Signed,
        block_hash: None,
        block_height: None,
        confirmations: 0,
    })?;
    store.upsert_process_withdrawal(&ProcessWithdrawal {
        solana_signature: authorize_signature.to_string(),
        solana_slot: authorize_meta.slot,
        block_time: authorize_meta.block_time,
        request_start_index: request_start,
        request_end_index: request_end,
        snapshot_root: state.withdrawal_snapshot.requested_withdrawals_tree_root,
        dogecoin_raw_hash: relayed.raw_hash,
        return_output_index: 0,
        return_output_amount_sats: 0,
        old_spent_txo_root: [0u8; 32],
        new_spent_txo_root: [0u8; 32],
        status: OperatorStatus::Signed,
    })?;
    store.link_reservation_to_withdrawal(
        &reservation_id,
        Some(selected.index),
        Some(&authorize_signature.to_string()),
    )?;

    if !args.broadcast_enabled {
        let evidence = Evidence {
            schema: "doge-local-process-withdrawal-v3-output-only".into(),
            stage: "SIGNED_NOT_BROADCAST".into(),
            completed: false,
            request: json!({
                "index": selected.index,
                "burnSignature": selected.record.signature.to_string(),
                "slot": selected.record.slot,
                "user": selected.record.user_pubkey.to_string(),
                "grossAmountSats": selected.record.amount_sats,
                "feeAmountSats": fee.fees_generated,
                "recipientAmountSats": fee.amount_after_fees,
                "addressType": selected.record.address_type,
                "recipientPayloadHex": hex::encode(selected.record.recipient_address),
                "recipientRegtestAddress": recipient_address,
                "snapshotSignature": snapshot_signature.to_string(),
            }),
            authorize: json!({
                "signature": authorize_signature.to_string(),
                "slot": authorize_meta.slot,
                "pendingPda": pending_pda.to_string(),
                "intentHashHex": hex::encode(intent_hash),
                "utx0HashHex": hex::encode(prepared.utx0_hash),
                "unsignedTxHashHex": hex::encode(prepared.unsigned_tx_hash),
                "utx0Buffer": utx0_buffer.to_string(),
                "requestStart": request_start,
                "requestEnd": request_end,
                "managerSetIndex": args.manager_set_index,
                "inputCount": prepared.utx0.inputs.len(),
                "noopVerified": true,
                "noopProgram": noop.emitter.to_string(),
                "sequence": sequence,
                "activeIntentHashHex": hex::encode(post_authorize_state.active_withdrawal_intent_hash),
            }),
            relay: json!({
                "managerServiceUrl": args.manager_service_url,
                "electrsUrl": args.electrs_url,
                "vaaHashHex": hex::encode(relayed.evidence.vaa_hash),
                "vaaSequence": sequence,
                "signedVaaBytes": relayed.evidence.signed_vaa_bytes,
                "signedVaaSha256Hex": hex::encode(relayed.evidence.signed_vaa_sha256),
                "managerSetIndex": args.manager_set_index,
                "signatureCount": relayed.evidence.signature_count,
                "quorum": relayed.evidence.required,
                "managerTotal": relayed.evidence.total,
                "signerIndices": relayed.evidence.signer_indices,
                "txid": relayed.txid_text,
                "finalTxidInternalHex": hex::encode(relayed.final_txid),
                "signedRawBytes": relayed.raw_bytes.len(),
                "broadcast": false,
                "signedRawSha256Hex": hex::encode(relayed.raw_hash),
            }),
            confirmation: json!({"status": "NOT_ATTEMPTED"}),
            finalize: json!({
                "status": "NOT_ATTEMPTED",
                "instruction": "finalize_confirmed_withdrawal",
                "discriminator": 17,
                "finalizeConfirmed": false,
            }),
            custody: json!({
                "operatorStore": args.operator_store,
                "reservationId": reservation_id,
                "selectedTotalSats": selected_sats,
                "minerFeeSats": args.fee_sats,
                "changeRegistered": false,
            }),
        };
        write_evidence(&args.evidence_path, &evidence)?;
    }
    // Dry-run: stop after the relay/signed-transaction recording.
    if !args.broadcast_enabled {
        println!(
            "[dry-run] broadcast skipped (broadcast_enabled=false); signed tx hex: {}",
            hex::encode(&relayed.raw_bytes)
        );
        println!("[dry-run] local txid: {}", hex::encode(relayed.final_txid));
        println!("[dry-run] confirmation (Stage 4) and finalization (Stage 5) skipped");
        return Ok(());
    }
    store.mark_reservation_broadcast(&reservation_id, &relayed.final_txid)?;
    store.upsert_dogecoin_transaction(&DogecoinTransaction {
        raw_hash: relayed.raw_hash,
        txid: Some(relayed.final_txid),
        raw_transaction: Some(relayed.raw_bytes.clone()),
        status: OperatorStatus::Broadcast,
        block_hash: None,
        block_height: None,
        confirmations: 0,
    })?;
    store.set_process_withdrawal_status(
        &authorize_signature.to_string(),
        OperatorStatus::Broadcast,
    )?;
    store.set_withdrawal_request_status(selected.index, OperatorStatus::Broadcast)?;

    // ── Stage 4: Confirm ───────────────────────────────────────────────────

    let mining_address = doge
        .call("getnewaddress", json!([]))
        .await?
        .as_str()
        .ok_or_else(|| anyhow!("getnewaddress result is not a string"))?
        .to_owned();
    doge.call(
        "generatetoaddress",
        json!([args.mine_blocks, mining_address]),
    )
    .await?;
    let verbose = wait_for_doge_confirmation(
        &doge,
        &relayed.txid_text,
        args.min_confirmations,
        Duration::from_secs(args.confirmation_timeout_secs),
        Duration::from_millis(args.poll_interval_ms),
    )
    .await?;
    let (withdrawal_vout, paid_sats) = extract_vout_and_sats(&verbose, &recipient_address)?;
    if withdrawal_vout != 0 || paid_sats != fee.amount_after_fees {
        bail!(
            "confirmed recipient output is vout {withdrawal_vout} with {paid_sats} sats; expected vout 0 with {} sats",
            fee.amount_after_fees
        );
    }
    let confirmed_raw_hex = doge
        .call("getrawtransaction", json!([relayed.txid_text, false]))
        .await?
        .as_str()
        .ok_or_else(|| anyhow!("getrawtransaction result is not hex"))?
        .to_owned();
    let confirmed_raw_bytes =
        hex::decode(confirmed_raw_hex).context("decode confirmed raw Dogecoin transaction")?;
    if confirmed_raw_bytes != relayed.raw_bytes {
        bail!("confirmed Dogecoin transaction differs from the manager-signed bytes");
    }
    let final_txid = double_sha256(&confirmed_raw_bytes);
    if final_txid != relayed.final_txid {
        bail!("confirmed Dogecoin transaction txid changed after broadcast");
    }
    let confirmations = verbose
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    let (block_hash, block_height, tx_index_in_block, block_txids) =
        confirmed_position(&doge, &verbose, &relayed.txid_text).await?;

    // Register the change UTXO (custody management — operator responsibility).
    let change_utxo = if let (Some(change_hash), Some(change_address)) = (
        prepared.change_script_hash,
        prepared.change_address.as_ref(),
    ) {
        let (change_vout, change_sats) = extract_vout_and_sats(&verbose, change_address)?;
        if change_vout != 1 || change_sats != plan.change_sats {
            bail!(
                "confirmed change output is vout {change_vout} with {change_sats} sats; expected vout 1 with {} sats",
                plan.change_sats
            );
        }
        let change_vout_u16 = u16::try_from(change_vout)
            .map_err(|_| anyhow!("change vout {change_vout} exceeds combined-index width"))?;
        let change_leaf =
            custody_ops::compute_combined_index(block_height, tx_index_in_block, change_vout_u16);
        Some(CustodyUtxo {
            txid: final_txid,
            vout: change_vout,
            amount_sats: plan.change_sats,
            script_pubkey_hex: hex::encode(p2sh_script_pubkey(&change_hash)),
            custody_address: change_address.clone(),
            key_reference: "wormhole-local-manager-set-0".into(),
            confirmation_block_hash: Some(block_hash),
            confirmation_height: Some(block_height),
            confirmations,
            leaf_index: change_leaf,
            status: CustodyUtxoStatus::Available,
            reservation_id: None,
            spend_txid: None,
            source_deposit_txid: None,
            source_solana_signature: Some(authorize_signature.to_string()),
            spend_request_index: None,
            spend_process_signature: None,
            original_recipient_address: [0u8; 32],
        })
    } else {
        None
    };

    store.upsert_dogecoin_transaction(&DogecoinTransaction {
        raw_hash: relayed.raw_hash,
        txid: Some(final_txid),
        raw_transaction: Some(confirmed_raw_bytes.clone()),
        status: OperatorStatus::Confirmed,
        block_hash: Some(block_hash),
        block_height: Some(block_height),
        confirmations,
    })?;

    // ── Stage 5: Finalize ──────────────────────────────────────────────────

    // Compute the transaction Merkle branch for inclusion proof.
    let tx_merkle_branch = compute_tx_merkle_branch(&block_txids, tx_index_in_block)?;

    // Create generic buffer with the exact signed transaction bytes.
    let signed_tx_buffer = create_generic_buffer(
        &solana_rpc,
        &payer,
        args.generic_buffer_program,
        &confirmed_raw_bytes,
    )
    .await?;
    verify_generic_buffer(
        &solana_rpc,
        signed_tx_buffer,
        args.generic_buffer_program,
        payer.pubkey(),
        &confirmed_raw_bytes,
    )
    .await?;

    let finalize_ix = instructions::finalize_confirmed_withdrawal(
        args.doge_bridge_program,
        payer.pubkey(),
        signed_tx_buffer,
        intent_hash,
        &tx_merkle_branch,
        tx_index_in_block as u32,
        block_height,
    );
    let finalize_signature = send_solana_transaction(&solana_rpc, &payer, &[finalize_ix], &[])
        .await
        .context("submit permissionless finalize_confirmed_withdrawal discriminator 17")?;
    let finalize_meta = solana_rpc
        .get_transaction(&finalize_signature, UiTransactionEncoding::Base64)
        .await
        .context("fetch finalize_confirmed_withdrawal transaction")?;

    let finalized_state = bridge_client
        .get_current_bridge_state()
        .await
        .context("read bridge state after finalize_confirmed_withdrawal")?;
    verify_finalized_state_advanced(&finalized_state, &state, request_end, final_txid)?;
    let pending_finalized =
        read_pending_withdrawal(&solana_rpc, pending_pda, args.doge_bridge_program).await?;
    if pending_finalized.status != PENDING_WITHDRAWAL_STATUS_FINALIZED
        || pending_finalized.final_txid != final_txid
    {
        bail!("pending withdrawal did not record the finalized Dogecoin txid");
    }

    if let Some(change) = change_utxo.as_ref() {
        store
            .finalize_custody_spend(&reservation_id, change, &final_txid)
            .map_err(|error| anyhow!("finalize custody spend failed: {error}"))?;
    } else {
        store.mark_reservation_spent(&reservation_id)?;
    }
    store.set_process_withdrawal_status(
        &authorize_signature.to_string(),
        OperatorStatus::Confirmed,
    )?;
    store.map_process_range_to_txid(&authorize_signature.to_string(), &final_txid)?;
    store.set_withdrawal_request_status(selected.index, OperatorStatus::Confirmed)?;

    let evidence = Evidence {
        schema: "doge-local-process-withdrawal-v3-output-only".into(),
        stage: "CONFIRMED_FINALIZED".into(),
        completed: true,
        request: json!({
            "index": selected.index,
            "burnSignature": selected.record.signature.to_string(),
            "slot": selected.record.slot,
            "user": selected.record.user_pubkey.to_string(),
            "grossAmountSats": selected.record.amount_sats,
            "feeAmountSats": fee.fees_generated,
            "recipientAmountSats": fee.amount_after_fees,
            "addressType": selected.record.address_type,
            "recipientPayloadHex": hex::encode(selected.record.recipient_address),
            "recipientRegtestAddress": recipient_address,
            "snapshotSignature": snapshot_signature.to_string(),
        }),
        authorize: json!({
            "signature": authorize_signature.to_string(),
            "slot": authorize_meta.slot,
            "pendingPda": pending_pda.to_string(),
            "intentHashHex": hex::encode(intent_hash),
            "utx0HashHex": hex::encode(prepared.utx0_hash),
            "unsignedTxHashHex": hex::encode(prepared.unsigned_tx_hash),
            "utx0Buffer": utx0_buffer.to_string(),
            "requestStart": request_start,
            "requestEnd": request_end,
            "managerSetIndex": args.manager_set_index,
            "inputCount": prepared.utx0.inputs.len(),
            "noopVerified": true,
            "noopProgram": noop.emitter.to_string(),
            "sequence": sequence,
            "activeIntentHashHex": hex::encode(post_authorize_state.active_withdrawal_intent_hash),
        }),
        relay: json!({
            "managerServiceUrl": args.manager_service_url,
            "electrsUrl": args.electrs_url,
            "vaaHashHex": hex::encode(relayed.evidence.vaa_hash),
            "vaaSequence": sequence,
            "signedVaaBytes": relayed.evidence.signed_vaa_bytes,
            "signedVaaSha256Hex": hex::encode(relayed.evidence.signed_vaa_sha256),
            "managerSetIndex": args.manager_set_index,
            "signatureCount": relayed.evidence.signature_count,
            "quorum": relayed.evidence.required,
            "managerTotal": relayed.evidence.total,
            "signerIndices": relayed.evidence.signer_indices,
            "txid": relayed.txid_text,
            "finalTxidInternalHex": hex::encode(relayed.final_txid),
            "signedRawBytes": relayed.raw_bytes.len(),
            "signedRawSha256Hex": hex::encode(relayed.raw_hash),
            "broadcast": true,
        }),
        confirmation: json!({
            "status": "CONFIRMED",
            "finalTxidInternalHex": hex::encode(final_txid),
            "blockHashInternalHex": hex::encode(block_hash),
            "blockHeight": block_height,
            "txIndexInBlock": tx_index_in_block,
            "confirmations": confirmations,
            "recipientVout": withdrawal_vout,
            "changeSats": plan.change_sats,
            "transactionMerkleBranchHex": tx_merkle_branch.iter().map(hex::encode).collect::<Vec<_>>(),
        }),
        finalize: json!({
            "status": "FINALIZED",
            "instruction": "finalize_confirmed_withdrawal",
            "discriminator": 17,
            "permissionless": true,
            "finalizeConfirmed": true,
            "signature": finalize_signature.to_string(),
            "slot": finalize_meta.slot,
            "processedIndex": finalized_state.next_processed_withdrawals_index,
            "activeIntentCleared": finalized_state.active_withdrawal_intent_hash == [0u8; 32],
            "signedTxBuffer": signed_tx_buffer.to_string(),
        }),
        custody: json!({
            "operatorStore": args.operator_store,
            "reservationId": reservation_id,
            "selectedTotalSats": selected_sats,
            "minerFeeSats": args.fee_sats,
            "changeRegistered": change_utxo.is_some(),
            "selectedUtxos": reserved_utxos.iter().map(|utxo| json!({
                "txidInternalHex": hex::encode(utxo.txid),
                "vout": utxo.vout,
                "amountSats": utxo.amount_sats,
                "leafIndex": utxo.leaf_index,
                "originalRecipientHex": hex::encode(utxo.original_recipient_address),
            })).collect::<Vec<_>>(),
        }),
    };
    write_evidence(&args.evidence_path, &evidence)
}

fn write_evidence(path: &Path, evidence: &Evidence) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(evidence)?)
        .with_context(|| format!("write {}", path.display()))?;
    println!("{}", serde_json::to_string_pretty(evidence)?);
    Ok(())
}

fn build_prepared_transaction(
    selected: &IndexedRequest,
    reserved_utxos: &[CustodyUtxo],
    plan: &doge_local_ops::CustodyTransactionPlan,
    bridge_state_pda: Pubkey,
    manager_set_index: u32,
    manager_set: &ManagerSet,
    recipient_address: &str,
) -> Result<PreparedTransaction> {
    let emitter = bridge_state_pda.to_bytes();
    let mut inputs = Vec::with_capacity(reserved_utxos.len());
    let mut redeem_scripts = Vec::with_capacity(reserved_utxos.len());

    for utxo in reserved_utxos {
        let redeem_script = build_redeem_script(
            SOLANA_EMITTER_CHAIN,
            &emitter,
            &utxo.original_recipient_address,
            manager_set.m,
            &manager_set.pubkeys,
        )?;
        let script_hash = hash160(&redeem_script);
        let derived_address = dogecoin_regtest_address(1, script_hash)?;
        if derived_address != utxo.custody_address {
            bail!(
                "custody UTXO {}:{} address {} does not match derived P2SH address {}",
                hex::encode(utxo.txid),
                utxo.vout,
                utxo.custody_address,
                derived_address
            );
        }
        let expected_script_pubkey = hex::encode(p2sh_script_pubkey(&script_hash));
        if !utxo.script_pubkey_hex.is_empty()
            && !utxo
                .script_pubkey_hex
                .eq_ignore_ascii_case(&expected_script_pubkey)
        {
            bail!(
                "custody UTXO {}:{} scriptPubKey does not match its derived redeem script",
                hex::encode(utxo.txid),
                utxo.vout
            );
        }

        let mut transaction_id = utxo.txid;
        transaction_id.reverse();
        inputs.push(Utx0Input {
            original_recipient_address: utxo.original_recipient_address,
            transaction_id,
            vout: utxo.vout,
        });
        redeem_scripts.push(redeem_script);
    }

    let recipient_type = UtxoAddressType::from_u32(selected.record.address_type)?;
    let mut outputs = vec![Utx0Output {
        amount: plan.recipient_sats,
        address_type: recipient_type,
        address: selected.record.recipient_address.to_vec(),
    }];

    let (change_script_hash, change_address) = if plan.change_sats == 0 {
        (None, None)
    } else {
        let change_redeem_script = build_redeem_script(
            SOLANA_EMITTER_CHAIN,
            &emitter,
            &[0u8; 32],
            manager_set.m,
            &manager_set.pubkeys,
        )?;
        let change_hash = hash160(&change_redeem_script);
        let change_address = dogecoin_regtest_address(1, change_hash)?;
        if change_address == recipient_address {
            bail!("derived change address equals the withdrawal recipient address");
        }
        outputs.push(Utx0Output {
            amount: plan.change_sats,
            address_type: UtxoAddressType::P2sh,
            address: change_hash.to_vec(),
        });
        (Some(change_hash), Some(change_address))
    };

    let utx0 = Utx0UnlockPayload {
        destination_chain: DOGECOIN_CHAIN_ID,
        delegated_manager_set_index: manager_set_index,
        inputs,
        outputs,
    };
    let utx0_bytes = utx0.serialize()?;
    let unsigned_tx = UnsignedTransaction::from_utx0(&utx0, redeem_scripts)?;
    let unsigned_tx_bytes = unsigned_tx.serialize();
    let utx0_hash = hash_impl_sha256_bytes(&utx0_bytes);
    let unsigned_tx_hash = hash_impl_sha256_bytes(&unsigned_tx_bytes);

    Ok(PreparedTransaction {
        utx0,
        utx0_bytes,
        unsigned_tx_bytes,
        utx0_hash,
        unsigned_tx_hash,
        change_script_hash,
        change_address,
    })
}

async fn register_local_withdrawal(
    client: &HttpClient,
    manager_service_url: &str,
    emitter: Pubkey,
    sequence: u64,
    payload: &[u8],
) -> Result<()> {
    let url = format!(
        "{}/api/v1/withdrawals",
        manager_service_url.trim_end_matches('/')
    );
    let response = client
        .post(&url)
        .json(&RegisterWithdrawalRequest {
            emitter_chain: SOLANA_EMITTER_CHAIN,
            emitter_address_hex: hex::encode(emitter.to_bytes()),
            sequence,
            payload_hex: hex::encode(payload),
        })
        .send()
        .await
        .with_context(|| format!("register withdrawal with {url}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("read manager registration response")?;
    if !status.is_success() {
        bail!("manager registration returned {status}: {body}");
    }
    let registered: RegisterWithdrawalResponse =
        serde_json::from_str(&body).context("decode manager registration response")?;
    if registered.sequence != sequence {
        bail!(
            "manager registration returned sequence {}, expected {sequence}",
            registered.sequence
        );
    }
    Ok(())
}

async fn relay_and_broadcast(
    client: &HttpClient,
    manager_service_url: &str,
    electrs_url: &str,
    emitter: Pubkey,
    sequence: u64,
    manager_set_index: u32,
    manager_set: &ManagerSet,
    prepared: &PreparedTransaction,
    poll_interval: Duration,
    timeout: Duration,
    manager_signing_enabled: bool,
    broadcast_enabled: bool,
) -> Result<RelayedTransaction> {
    let emitter_bytes = emitter.to_bytes();
    // Dry-run (manager_signing_enabled=false): fetch whatever signatures the
    // Manager service already has once, without polling for new ones. Full
    // mode: poll until the service reports the signature set is complete.
    let signatures = if manager_signing_enabled {
        wait_for_manager_signatures(
            client,
            manager_service_url,
            &emitter_bytes,
            sequence,
            poll_interval,
            timeout,
        )
        .await?
    } else {
        println!("[dry-run] manager signing skipped (manager_signing_enabled=false); fetching pre-existing signatures once");
        fetch_manager_signatures(
            client,
            manager_service_url,
            SOLANA_EMITTER_CHAIN,
            &emitter_bytes,
            sequence,
        )
        .await?
    };
    if signatures.destination_chain != DOGECOIN_CHAIN_ID
        || signatures.manager_set_index != manager_set_index
        || signatures.required != manager_set.m as u32
        || signatures.total != manager_set.n as u32
    {
        bail!("manager response metadata does not match the prepared UTX0/manager set");
    }

    let signed_vaa = fetch_signed_vaa(
        client,
        manager_service_url,
        SOLANA_EMITTER_CHAIN,
        &emitter_bytes,
        sequence,
    )
    .await?;
    if !vaa_hash_matches(&signed_vaa, &signatures.vaa_hash)? {
        bail!(
            "manager vaaHash {} does not match signed VAA digest {}",
            hex::encode(signatures.vaa_hash),
            hex::encode(vaa_signing_digest(&signed_vaa)?)
        );
    }
    let vaa = parse_vaa(&signed_vaa)?;
    if vaa.emitter_chain != SOLANA_EMITTER_CHAIN
        || vaa.emitter_address != emitter_bytes
        || vaa.sequence != sequence
        || vaa.payload != prepared.utx0_bytes
    {
        bail!("signed VAA does not match the emitted withdrawal identity/payload");
    }
    let decoded_payload = Utx0UnlockPayload::parse(&vaa.payload)?;
    if decoded_payload != prepared.utx0 {
        bail!("signed VAA UTX0 differs from the prepared payload");
    }

    let relay_evidence = RelayEvidence {
        vaa_hash: signatures.vaa_hash,
        signed_vaa_sha256: hash_impl_sha256_bytes(&signed_vaa),
        signed_vaa_bytes: signed_vaa.len(),
        signature_count: signatures.signatures.len(),
        required: signatures.required,
        total: signatures.total,
        signer_indices: signatures
            .signatures
            .iter()
            .map(|signer| signer.signer_index)
            .collect(),
    };
    let redeem_scripts = prepared
        .utx0
        .inputs
        .iter()
        .map(|input| {
            build_redeem_script(
                SOLANA_EMITTER_CHAIN,
                &emitter_bytes,
                &input.original_recipient_address,
                manager_set.m,
                &manager_set.pubkeys,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let mut transaction = UnsignedTransaction::from_utx0(&prepared.utx0, redeem_scripts)?;
    if transaction.serialize() != prepared.unsigned_tx_bytes {
        bail!("relay reconstructed different unsigned Dogecoin transaction bytes");
    }
    let sighashes = (0..transaction.input_count())
        .map(|input_index| transaction.sighash_all(input_index))
        .collect::<Result<Vec<_>>>()?;

    let mut seen_signers = HashSet::new();
    let mut per_input = vec![Vec::<(u8, Vec<u8>)>::new(); transaction.input_count()];
    for signer in &signatures.signatures {
        if !seen_signers.insert(signer.signer_index) {
            bail!(
                "manager response contains duplicate signer {}",
                signer.signer_index
            );
        }
        let signer_index = signer.signer_index as usize;
        let public_key = manager_set
            .pubkeys
            .get(signer_index)
            .ok_or_else(|| anyhow!("manager signer index {signer_index} is out of range"))?;
        if signer.input_signatures.len() != transaction.input_count() {
            bail!(
                "manager signer {signer_index} returned {} input signatures, expected {}",
                signer.input_signatures.len(),
                transaction.input_count()
            );
        }
        for (input_index, signature) in signer.input_signatures.iter().enumerate() {
            if signature.last().copied() != Some(1) {
                bail!("manager signer {signer_index} input {input_index} did not use SIGHASH_ALL");
            }
            if !verify_manager_signature(public_key, &sighashes[input_index], signature)? {
                bail!("manager signer {signer_index} input {input_index} signature is invalid");
            }
            per_input[input_index].push((signer.signer_index, signature.clone()));
        }
    }

    let dry_run = !manager_signing_enabled;
    let mut have_quorum = true;
    for (input_index, candidates) in per_input.iter_mut().enumerate() {
        candidates.sort_by_key(|(signer_index, _)| *signer_index);
        if candidates.len() < manager_set.m as usize {
            have_quorum = false;
            if dry_run {
                println!(
                    "[dry-run] input {input_index} has {}/{} valid manager signatures; scriptSig assembly skipped",
                    candidates.len(),
                    manager_set.m
                );
                continue;
            }
            bail!(
                "input {input_index} has {} valid manager signatures, need {}",
                candidates.len(),
                manager_set.m
            );
        }
        let selected_signatures = candidates
            .iter()
            .take(manager_set.m as usize)
            .map(|(_, signature)| signature.clone())
            .collect::<Vec<_>>();
        transaction.apply_script_sig(input_index, &selected_signatures)?;
    }

    let raw_bytes = transaction.serialize();
    let final_txid = double_sha256(&raw_bytes);
    let expected_display_txid = hex::encode(transaction.txid());
    let txid_text = if broadcast_enabled {
        let txid_text = broadcast_electrs(client, electrs_url, &hex::encode(&raw_bytes)).await?;
        if !txid_text.eq_ignore_ascii_case(&expected_display_txid) {
            bail!(
                "electrs returned txid {txid_text}, locally assembled transaction is {expected_display_txid}"
            );
        }
        let displayed_internal = decode_displayed_hash32("electrs txid", &txid_text)?;
        if displayed_internal != final_txid {
            bail!("electrs txid byte order does not match the signed transaction");
        }
        txid_text
    } else {
        println!("[dry-run] broadcast skipped (broadcast_enabled=false)");
        if have_quorum {
            println!("[dry-run] signed tx hex: {}", hex::encode(&raw_bytes));
        } else {
            println!(
                "[dry-run] unsigned tx hex (quorum not reached): {}",
                hex::encode(&raw_bytes)
            );
        }
        expected_display_txid
    };

    Ok(RelayedTransaction {
        raw_hash: hash_impl_sha256_bytes(&raw_bytes),
        raw_bytes,
        final_txid,
        txid_text,
        evidence: relay_evidence,
    })
}

async fn wait_for_manager_signatures(
    client: &HttpClient,
    manager_service_url: &str,
    emitter: &[u8; 32],
    sequence: u64,
    poll_interval: Duration,
    timeout: Duration,
) -> Result<ManagerSignatures> {
    let started = Instant::now();
    let mut last_error = None;
    loop {
        match fetch_manager_signatures(
            client,
            manager_service_url,
            SOLANA_EMITTER_CHAIN,
            emitter,
            sequence,
        )
        .await
        {
            Ok(response) if response.is_complete => return Ok(response),
            Ok(response) => {
                last_error = Some(format!(
                    "manager response incomplete with {} signers",
                    response.signatures.len()
                ));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        if started.elapsed() >= timeout {
            bail!(
                "timed out waiting for manager signatures: {}",
                last_error.unwrap_or_else(|| "no response".into())
            );
        }
        sleep(poll_interval).await;
    }
}

async fn broadcast_electrs(
    client: &HttpClient,
    electrs_url: &str,
    raw_hex: &str,
) -> Result<String> {
    let url = format!("{}/tx", electrs_url.trim_end_matches('/'));
    let response = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(raw_hex.to_owned())
        .send()
        .await
        .with_context(|| format!("broadcast Dogecoin transaction through {url}"))?;
    let status = response.status();
    let body = response.text().await.context("read electrs response")?;
    if !status.is_success() {
        bail!("electrs broadcast returned {status}: {body}");
    }
    Ok(body.trim().trim_matches('"').to_owned())
}

/// Verify the pending PDA after authorize_withdrawal: status must be
/// PENDING_VAA and the authorization bindings must match.
fn verify_pending_authorized(
    pending: &PendingWithdrawal,
    intent_hash: [u8; 32],
    request_start: u64,
    request_end: u64,
    manager_set_index: u32,
    utx0_hash: [u8; 32],
    unsigned_tx_hash: [u8; 32],
) -> Result<()> {
    if pending.status != PENDING_WITHDRAWAL_STATUS_PENDING_VAA
        || pending.intent_hash != intent_hash
        || pending.request_start != request_start
        || pending.request_end != request_end
        || pending.manager_set_index != manager_set_index
        || pending.utx0_hash != utx0_hash
        || pending.unsigned_tx_hash != unsigned_tx_hash
    {
        bail!("authorized PendingWithdrawal PDA does not match the submitted intent");
    }
    Ok(())
}

/// Authorization must not advance the withdrawal cursor or mutate finalized
/// bridge state. Only `active_withdrawal_intent_hash` should change.
fn verify_authorize_state_unchanged(
    before: &doge_bridge_client::PsyBridgeProgramState,
    after: &doge_bridge_client::PsyBridgeProgramState,
    expected_intent_hash: [u8; 32],
) -> Result<()> {
    if after.last_return_output != before.last_return_output
        || after.spent_txo_tree_root != before.spent_txo_tree_root
        || after.next_processed_withdrawals_index != before.next_processed_withdrawals_index
        || after.total_spent_deposit_utxo_count != before.total_spent_deposit_utxo_count
    {
        bail!("authorize_withdrawal mutated finalized bridge state before Dogecoin confirmation");
    }
    if after.active_withdrawal_intent_hash != expected_intent_hash {
        bail!(
            "authorize_withdrawal did not set active_withdrawal_intent_hash to the expected intent"
        );
    }
    Ok(())
}

/// Finalization must advance the withdrawal cursor to request_end, clear the
/// active intent, and append the final_txid to the sent-transactions tree.
fn verify_finalized_state_advanced(
    finalized: &doge_bridge_client::PsyBridgeProgramState,
    pre_authorize: &doge_bridge_client::PsyBridgeProgramState,
    request_end: u64,
    _final_txid: [u8; 32],
) -> Result<()> {
    if finalized.next_processed_withdrawals_index != request_end {
        bail!(
            "finalize did not advance cursor: expected {}, got {}",
            request_end,
            finalized.next_processed_withdrawals_index
        );
    }
    if finalized.active_withdrawal_intent_hash != [0u8; 32] {
        bail!("finalize did not clear active_withdrawal_intent_hash");
    }
    // The sent-transactions tree should have grown by exactly one leaf.
    let expected_sent_count = pre_authorize.sent_transactions_tree.next_index + 1;
    if finalized.sent_transactions_tree.next_index != expected_sent_count {
        bail!(
            "finalize did not append exactly one leaf to sent_transactions_tree: expected next_index {}, got {}",
            expected_sent_count,
            finalized.sent_transactions_tree.next_index
        );
    }
    // The appended leaf is verified on-chain via the Merkle branch; locally we
    // only confirm the tree grew by exactly one leaf.
    Ok(())
}

fn pending_withdrawal_pda(program_id: Pubkey, intent_hash: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"pending_withdrawal", intent_hash], &program_id).0
}

async fn read_pending_withdrawal(
    rpc: &RpcClient,
    address: Pubkey,
    expected_owner: Pubkey,
) -> Result<PendingWithdrawal> {
    let account = rpc
        .get_account(&address)
        .await
        .with_context(|| format!("read PendingWithdrawal account {address}"))?;
    if account.owner != expected_owner {
        bail!(
            "PendingWithdrawal {address} owner {} != {expected_owner}",
            account.owner
        );
    }
    if account.data.len() < PendingWithdrawal::SIZE {
        bail!(
            "PendingWithdrawal {address} has {} bytes, expected at least {}",
            account.data.len(),
            PendingWithdrawal::SIZE
        );
    }
    Ok(bytemuck::pod_read_unaligned(
        &account.data[..PendingWithdrawal::SIZE],
    ))
}

async fn verify_generic_buffer(
    rpc: &RpcClient,
    address: Pubkey,
    expected_owner: Pubkey,
    expected_writer: Pubkey,
    payload: &[u8],
) -> Result<()> {
    let account = rpc
        .get_account(&address)
        .await
        .with_context(|| format!("read generic buffer {address}"))?;
    if account.owner != expected_owner {
        bail!("generic buffer owner mismatch");
    }
    if account.data.len() != GENERIC_BUFFER_HEADER_SIZE + payload.len()
        || account.data[..GENERIC_BUFFER_HEADER_SIZE] != expected_writer.to_bytes()
        || account.data[GENERIC_BUFFER_HEADER_SIZE..] != *payload
    {
        bail!("generic buffer is not the exact 32-byte header plus payload");
    }
    Ok(())
}

/// Extract (block_hash, block_height, tx_index, txids) from a confirmed
/// Dogecoin transaction. The txids are the displayed (big-endian) hex strings
/// from `getblock`, suitable for `decode_displayed_hash32`.
async fn confirmed_position(
    rpc: &DogeRpc,
    verbose_transaction: &Value,
    txid: &str,
) -> Result<([u8; 32], u32, u16, Vec<String>)> {
    let block_hash_text = verbose_transaction
        .get("blockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("confirmed transaction missing blockhash"))?;
    let block_hash = decode_displayed_hash32("Dogecoin block hash", block_hash_text)?;
    let header = rpc
        .call("getblockheader", json!([block_hash_text, true]))
        .await?;
    let height_u64 = header
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("getblockheader missing height"))?;
    let height = u32::try_from(height_u64)
        .map_err(|_| anyhow!("Dogecoin block height {height_u64} exceeds u32"))?;
    let block = rpc.call("getblock", json!([block_hash_text, 1])).await?;
    let txids = block
        .get("tx")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("getblock missing tx array"))?;
    let index = txids
        .iter()
        .position(|value| value.as_str() == Some(txid))
        .ok_or_else(|| anyhow!("confirmed txid not present in its reported block"))?;
    let index = u16::try_from(index)
        .map_err(|_| anyhow!("transaction index {index} exceeds combined-index width"))?;
    let txid_strings = txids
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    Ok((block_hash, height, index, txid_strings))
}

/// Compute the Dogecoin transaction Merkle branch (internal-order sibling
/// hashes) for the transaction at `tx_index` within the block's txid list.
/// The txids are displayed (big-endian) hex strings; they are reversed to
/// internal byte order before tree construction. Uses double-SHA256 pairing
/// with the standard odd-leaf duplication rule.
fn compute_tx_merkle_branch(txids_displayed: &[String], tx_index: u16) -> Result<Vec<[u8; 32]>> {
    let mut level: Vec<[u8; 32]> = txids_displayed
        .iter()
        .map(|hex| decode_displayed_hash32("block txid", hex))
        .collect::<Result<Vec<_>>>()?;
    if level.is_empty() {
        bail!("block has no transactions");
    }
    let mut branch = Vec::new();
    let mut index = tx_index as usize;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let sibling_index = index ^ 1;
        let sibling = level[sibling_index];
        branch.push(sibling);
        let mut parents = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&level[i]);
            pair[32..].copy_from_slice(&level[i + 1]);
            parents.push(double_sha256(&pair));
        }
        level = parents;
        index >>= 1;
    }
    Ok(branch)
}

fn hash160(bytes: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(bytes);
    Ripemd160::digest(sha).into()
}

fn read_keypair(path: &Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path).map_err(|error| anyhow!("read {role} keypair: {error}"))
}

fn clone_keypair(keypair: &Keypair) -> Result<Keypair> {
    Keypair::from_bytes(&keypair.to_bytes()).context("clone keypair")
}

async fn load_indexed_requests(args: &Args, bridge_state: Pubkey) -> Result<Vec<IndexedRequest>> {
    let config = HistorySyncConfig::new(
        args.solana_rpc_url.clone(),
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
    handle.join().await.context("join history sync")?;
    requests.sort_by_key(|request| request.slot);
    Ok(requests
        .into_iter()
        .enumerate()
        .map(|(index, record)| IndexedRequest {
            index: index as u64,
            record,
        })
        .collect())
}

fn select_request(
    requests: &[IndexedRequest],
    index: Option<u64>,
    signature: Option<&Signature>,
) -> Result<IndexedRequest> {
    match (index, signature) {
        (Some(index), None) => requests.iter().find(|request| request.index == index),
        (None, Some(signature)) => requests
            .iter()
            .find(|request| request.record.signature == *signature),
        _ => bail!("provide exactly one of --request-index or --request-signature"),
    }
    .cloned()
    .ok_or_else(|| anyhow!("withdrawal request not found in Solana history"))
}

fn ensure_next_unprocessed(request: &IndexedRequest, next: u64) -> Result<()> {
    if request.index != next {
        bail!(
            "withdrawal request index {} is not next unprocessed index {next}",
            request.index
        );
    }
    Ok(())
}

fn verify_snapshot(
    state: &doge_bridge_client::PsyBridgeProgramState,
    request: &IndexedRequest,
) -> Result<()> {
    let snapshot = state.withdrawal_snapshot;
    if request.index >= snapshot.next_requested_withdrawals_tree_index {
        bail!("selected withdrawal request is not in the current snapshot");
    }
    if snapshot.requested_withdrawals_tree_root != state.requested_withdrawals_tree.get_root()
        || snapshot.next_requested_withdrawals_tree_index
            != state.requested_withdrawals_tree.next_index
    {
        bail!("withdrawal snapshot does not match the requested-withdrawal tree");
    }
    Ok(())
}

fn dogecoin_regtest_address(address_type: u32, payload: [u8; 20]) -> Result<String> {
    let version = match address_type {
        0 => 0x6f,
        1 => 0xc4,
        other => bail!("unsupported Dogecoin address type {other}"),
    };
    let mut bytes = Vec::with_capacity(21);
    bytes.push(version);
    bytes.extend_from_slice(&payload);
    Ok(bs58::encode(bytes).with_check().into_string())
}

async fn verify_regtest(rpc: &DogeRpc) -> Result<()> {
    let chain = rpc
        .call("getblockchaininfo", json!([]))
        .await?
        .get("chain")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("getblockchaininfo missing chain"))?;
    if chain != "regtest" {
        bail!("refusing to run local-manager withdrawal on Dogecoin chain {chain}");
    }
    Ok(())
}

async fn wait_for_doge_confirmation(
    rpc: &DogeRpc,
    txid: &str,
    minimum: u32,
    timeout: Duration,
    interval: Duration,
) -> Result<Value> {
    let started = Instant::now();
    let mut last_status = "transaction not yet visible".to_owned();
    loop {
        match rpc.call("getrawtransaction", json!([txid, true])).await {
            Ok(transaction) => {
                let confirmations = transaction
                    .get("confirmations")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if confirmations >= minimum as u64 {
                    return Ok(transaction);
                }
                last_status = format!("{confirmations} confirmations");
            }
            Err(error) => last_status = error.to_string(),
        }
        if started.elapsed() >= timeout {
            bail!(
                "tx {txid} was not confirmed after {}s: {last_status}",
                timeout.as_secs()
            );
        }
        sleep(interval).await;
    }
}

/// Build authenticated burn-request membership witnesses for authorize_withdrawal.
///
/// For each request in `[start, end)`, this carries the leaf preimage and 32-level
/// FixedMerkleAppendTree sibling path checked directly by the bridge instruction.
/// This is not a zero-knowledge proof.
fn build_burn_request_proofs(
    history: &[IndexedRequest],
    state: &doge_bridge_client::PsyBridgeProgramState,
    request_start: u64,
    request_end: u64,
) -> Result<Vec<WithdrawalRequestProof>> {
    let snapshot_request_count = usize::try_from(
        state
            .withdrawal_snapshot
            .next_requested_withdrawals_tree_index,
    )
    .map_err(|_| anyhow!("snapshot request count exceeds usize"))?;
    let snapshot_history = history
        .get(..snapshot_request_count)
        .ok_or_else(|| anyhow!("withdrawal history does not cover the snapshot tree"))?;

    // Rebuild the tree to verify our history matches the snapshot root.
    let mut request_tree = FixedMerkleAppendTree::new_empty();
    for request in snapshot_history {
        let leaf = PsyWithdrawalRequest::new(
            request.record.recipient_address,
            request.record.net_amount_sats,
            request.record.address_type,
        )
        .to_leaf();
        request_tree.append(leaf);
    }
    if request_tree.get_root() != state.withdrawal_snapshot.requested_withdrawals_tree_root {
        bail!("withdrawal request history does not reconstruct the snapshot tree");
    }

    // Compute membership siblings for each request in the range.
    let mut proofs = Vec::new();
    for request_index in request_start..request_end {
        let request = snapshot_history
            .iter()
            .find(|r| r.index == request_index)
            .ok_or_else(|| anyhow!("request {request_index} not found in snapshot history"))?;
        let request_leaf = PsyWithdrawalRequest::new(
            request.record.recipient_address,
            request.record.net_amount_sats,
            request.record.address_type,
        );
        let siblings = request_membership_siblings(snapshot_history, request_index)?;
        proofs.push(WithdrawalRequestProof {
            request: request_leaf,
            siblings,
        });
    }
    Ok(proofs)
}

/// Compute the 32-level Merkle membership siblings for `request_index` in the
/// `FixedMerkleAppendTree` built from `history`. Uses `SHA256_ZERO_HASHES`
/// for missing nodes, matching the on-chain tree construction.
fn request_membership_siblings(
    history: &[IndexedRequest],
    request_index: u64,
) -> Result<[[u8; 32]; 32]> {
    if request_index >= history.len() as u64 {
        bail!("request proof index is absent from history");
    }
    let mut level = history
        .iter()
        .map(|request| {
            PsyWithdrawalRequest::new(
                request.record.recipient_address,
                request.record.net_amount_sats,
                request.record.address_type,
            )
            .to_leaf()
        })
        .collect::<Vec<_>>();
    let mut index = usize::try_from(request_index)?;
    let mut siblings = [[0u8; 32]; 32];
    for height in 0..32 {
        let sibling_index = index ^ 1;
        siblings[height] = level
            .get(sibling_index)
            .copied()
            .unwrap_or(SHA256_ZERO_HASHES[height]);
        let parent_len = (level.len() + 1) / 2;
        let mut parents = Vec::with_capacity(parent_len);
        for parent in 0..parent_len {
            let left = level
                .get(parent * 2)
                .copied()
                .unwrap_or(SHA256_ZERO_HASHES[height]);
            let right = level
                .get(parent * 2 + 1)
                .copied()
                .unwrap_or(SHA256_ZERO_HASHES[height]);
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            parents.push(hash_impl_sha256_bytes(&pair));
        }
        level = parents;
        index >>= 1;
    }
    Ok(siblings)
}

fn generic_buffer_chunks(data: &[u8]) -> impl Iterator<Item = Result<(u32, &[u8])>> {
    data.chunks(GENERIC_BUFFER_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            let offset = index
                .checked_mul(GENERIC_BUFFER_CHUNK_SIZE)
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or_else(|| anyhow!("generic buffer write offset exceeds u32"))?;
            Ok((offset, chunk))
        })
}

async fn create_generic_buffer(
    rpc: &RpcClient,
    payer: &Keypair,
    program_id: Pubkey,
    data: &[u8],
) -> Result<Pubkey> {
    let target_size =
        u32::try_from(data.len()).map_err(|_| anyhow!("generic buffer payload exceeds u32"))?;
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
        payer.pubkey(),
        target_size,
    );
    send_solana_transaction(rpc, payer, &[create, init], &[&account]).await?;
    for chunk in generic_buffer_chunks(data) {
        let (offset, chunk) = chunk?;
        let write = instructions::generic_buffer_write(
            program_id,
            account.pubkey(),
            payer.pubkey(),
            offset,
            chunk,
        );
        send_solana_transaction(rpc, payer, &[write], &[]).await?;
    }
    Ok(account.pubkey())
}

async fn create_generic_buffer_with_writer(
    rpc: &RpcClient,
    payer: &Keypair,
    writer: &Keypair,
    program_id: Pubkey,
    data: &[u8],
) -> Result<Pubkey> {
    let target_size =
        u32::try_from(data.len()).map_err(|_| anyhow!("generic buffer payload exceeds u32"))?;
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
    send_solana_transaction(rpc, payer, &[create, init], &[writer, &account]).await?;
    for chunk in generic_buffer_chunks(data) {
        let (offset, chunk) = chunk?;
        let write = instructions::generic_buffer_write(
            program_id,
            account.pubkey(),
            writer.pubkey(),
            offset,
            chunk,
        );
        send_solana_transaction(rpc, payer, &[write], &[writer]).await?;
    }
    Ok(account.pubkey())
}

fn operator_funding_requirement(
    operator_balance: u64,
    zero_data_rent_reserve: u64,
    pending_withdrawal_rent: u64,
    fee_prepay: u64,
) -> Result<(u64, u64)> {
    let required_balance = zero_data_rent_reserve
        .checked_add(pending_withdrawal_rent)
        .and_then(|balance| balance.checked_add(fee_prepay))
        .ok_or_else(|| anyhow!("operator authorize funding requirement overflow"))?;
    let top_up = if operator_balance >= required_balance {
        0
    } else {
        required_balance
            .checked_sub(operator_balance)
            .ok_or_else(|| anyhow!("operator authorize top-up underflow"))?
    };
    Ok((required_balance, top_up))
}

fn operator_funding_transfer_amount(
    payer: Pubkey,
    operator: Pubkey,
    top_up: u64,
) -> Result<Option<u64>> {
    if top_up == 0 {
        return Ok(None);
    }
    if payer == operator {
        bail!(
            "operator requires {top_up} additional lamports for authorize_withdrawal, but the configured payer and operator are the same account"
        );
    }
    Ok(Some(top_up))
}

async fn ensure_operator_authorize_funding(
    rpc: &RpcClient,
    payer: &Keypair,
    operator: &Keypair,
) -> Result<()> {
    let zero_data_rent_reserve = rpc
        .get_minimum_balance_for_rent_exemption(0)
        .await
        .context("read zero-data account rent exemption")?;
    let pending_withdrawal_rent = rpc
        .get_minimum_balance_for_rent_exemption(PendingWithdrawal::SIZE)
        .await
        .context("read PendingWithdrawal rent exemption")?;
    let operator_balance = rpc
        .get_balance(&operator.pubkey())
        .await
        .with_context(|| format!("read operator balance {}", operator.pubkey()))?;
    let (required_balance, top_up) = operator_funding_requirement(
        operator_balance,
        zero_data_rent_reserve,
        pending_withdrawal_rent,
        WORMHOLE_FEE_PREPAY_LAMPORTS,
    )?;
    let Some(transfer_amount) =
        operator_funding_transfer_amount(payer.pubkey(), operator.pubkey(), top_up)?
    else {
        return Ok(());
    };

    let transfer =
        system_instruction::transfer(&payer.pubkey(), &operator.pubkey(), transfer_amount);
    let signature = send_solana_transaction(rpc, payer, &[transfer], &[])
        .await
        .context("fund operator before authorize_withdrawal")?;
    println!(
        "Funded operator {} with {} lamports from payer {} before authorize_withdrawal (previous balance: {}, required balance: {}, transaction: {})",
        operator.pubkey(),
        transfer_amount,
        payer.pubkey(),
        operator_balance,
        required_balance,
        signature,
    );
    Ok(())
}

async fn send_solana_transaction(
    rpc: &RpcClient,
    payer: &Keypair,
    instructions: &[solana_sdk::instruction::Instruction],
    extra_signers: &[&Keypair],
) -> Result<Signature> {
    let blockhash = rpc.get_latest_blockhash().await?;
    let mut signers = vec![payer];
    for signer in extra_signers {
        if signer.pubkey() != payer.pubkey()
            && !signers
                .iter()
                .any(|existing| existing.pubkey() == signer.pubkey())
        {
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

async fn find_noop_message_for_programs(
    args: &Args,
    bridge_state: Pubkey,
    signature: &Signature,
) -> Result<doge_bridge_client::NoopShimWithdrawalMessage> {
    let mut program_ids = vec![args.noop_shim_program];
    if args.wormhole_shim_program != args.noop_shim_program {
        program_ids.push(args.wormhole_shim_program);
    }
    let mut last_error = None;
    for program_id in program_ids {
        let monitor = NoopShimMonitor::new(
            NoopShimMonitorConfig::new(args.solana_rpc_url.clone(), bridge_state)
                .noop_shim_program_id(program_id)
                .batch_size(50),
        )?;
        match find_noop_message(&monitor, signature).await {
            Ok(message) => return Ok(message),
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    bail!(
        "authorize signature {signature} not found in noop history: {}",
        last_error.unwrap_or_else(|| "no configured noop program".into())
    )
}

async fn find_noop_message(
    monitor: &NoopShimMonitor,
    signature: &Signature,
) -> Result<doge_bridge_client::NoopShimWithdrawalMessage> {
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
    bail!("authorize signature {signature} not found in noop history")
}

fn decode_displayed_hash32(name: &str, text: &str) -> Result<[u8; 32]> {
    let mut bytes = hex::decode(text.trim()).with_context(|| format!("decode {name}"))?;
    if bytes.len() != 32 {
        bail!("{name} must be 32 bytes, got {}", bytes.len());
    }
    bytes.reverse();
    Ok(bytes.try_into().expect("validated 32-byte hash"))
}

#[cfg(test)]
mod operator_funding_tests {
    use super::*;

    #[test]
    fn computes_exact_required_balance_and_top_up() {
        let (required_balance, top_up) =
            operator_funding_requirement(1_500, 900, 2_000, 1_000).unwrap();

        assert_eq!(required_balance, 3_900);
        assert_eq!(top_up, 2_400);
    }

    #[test]
    fn sufficient_operator_balance_requires_no_top_up() {
        assert_eq!(
            operator_funding_requirement(3_900, 900, 2_000, 1_000).unwrap(),
            (3_900, 0)
        );
        assert_eq!(
            operator_funding_requirement(4_000, 900, 2_000, 1_000).unwrap(),
            (3_900, 0)
        );
    }

    #[test]
    fn funding_requirement_rejects_overflow() {
        assert!(operator_funding_requirement(0, u64::MAX, 1, 0).is_err());
        assert!(operator_funding_requirement(0, u64::MAX - 1, 1, 1).is_err());
    }

    #[test]
    fn same_key_is_noop_without_shortfall_and_errors_with_shortfall() {
        let key = Pubkey::new_unique();
        assert_eq!(operator_funding_transfer_amount(key, key, 0).unwrap(), None);

        let error = operator_funding_transfer_amount(key, key, 1).unwrap_err();
        assert!(error
            .to_string()
            .contains("payer and operator are the same account"));
    }

    #[test]
    fn different_payer_transfers_exact_shortfall() {
        assert_eq!(
            operator_funding_transfer_amount(Pubkey::new_unique(), Pubkey::new_unique(), 2_400)
                .unwrap(),
            Some(2_400)
        );
    }
}

#[cfg(test)]
mod request_proof_tests {
    use super::*;

    fn request(index: u64, gross: u64, net: u64, recipient_byte: u8) -> IndexedRequest {
        IndexedRequest {
            index,
            record: WithdrawalRequestRecord {
                signature: Signature::new_unique(),
                slot: index + 1,
                block_time: None,
                amount_sats: gross,
                net_amount_sats: net,
                recipient_address: [recipient_byte; 20],
                address_type: 0,
                user_pubkey: Pubkey::new_unique(),
            },
        }
    }

    #[test]
    fn nonzero_fee_history_reconstructs_exact_net_leaf_root() {
        let history = vec![
            request(0, 50_000_000, 48_500_000, 0x11),
            request(1, 25_000_000, 23_750_000, 0x22),
        ];
        let mut expected_tree = FixedMerkleAppendTree::new_empty();
        for request in &history {
            expected_tree.append(
                PsyWithdrawalRequest::new(
                    request.record.recipient_address,
                    request.record.net_amount_sats,
                    request.record.address_type,
                )
                .to_leaf(),
            );
        }
        let mut state = doge_bridge_client::PsyBridgeProgramState::default();
        state
            .withdrawal_snapshot
            .next_requested_withdrawals_tree_index = history.len() as u64;
        state.withdrawal_snapshot.requested_withdrawals_tree_root = expected_tree.get_root();

        let proofs = build_burn_request_proofs(&history, &state, 0, 2).unwrap();
        assert_eq!(proofs[0].request.amount_sats, 48_500_000);
        assert_eq!(proofs[1].request.amount_sats, 23_750_000);

        let mut gross_tree = FixedMerkleAppendTree::new_empty();
        for request in &history {
            gross_tree.append(
                PsyWithdrawalRequest::new(
                    request.record.recipient_address,
                    request.record.amount_sats,
                    request.record.address_type,
                )
                .to_leaf(),
            );
        }
        assert_ne!(gross_tree.get_root(), expected_tree.get_root());
    }
}

#[cfg(test)]
mod generic_buffer_tests {
    use super::*;
    use solana_sdk::hash::Hash;

    #[test]
    fn max_two_signer_write_transaction_fits_with_safety_margin() {
        let payer = Keypair::new();
        let writer = Keypair::new();
        let write = instructions::generic_buffer_write(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            writer.pubkey(),
            0,
            &vec![0u8; GENERIC_BUFFER_CHUNK_SIZE],
        );
        let transaction = Transaction::new_signed_with_payer(
            &[write],
            Some(&payer.pubkey()),
            &[&payer, &writer],
            Hash::new_unique(),
        );
        let serialized_size = bincode::serialize(&transaction).unwrap().len();

        assert_eq!(
            serialized_size,
            GENERIC_BUFFER_WRITE_TRANSACTION_OVERHEAD + GENERIC_BUFFER_CHUNK_SIZE
        );
        assert!(
            serialized_size
                <= SOLANA_TRANSACTION_SIZE_LIMIT - GENERIC_BUFFER_WRITE_TRANSACTION_SAFETY_MARGIN,
            "serialized generic buffer write is {serialized_size} bytes"
        );
    }

    #[test]
    fn proof_payload_chunks_reconstruct_with_exact_offsets() {
        let proof: Vec<u8> = (0..1_056).map(|index| (index % 251) as u8).collect();
        let chunks = generic_buffer_chunks(&proof)
            .collect::<Result<Vec<_>>>()
            .unwrap();

        assert!(chunks.len() >= 2);
        let mut reconstructed = vec![0u8; proof.len()];
        let mut expected_offset = 0usize;
        for (offset, chunk) in chunks {
            let offset = offset as usize;
            assert_eq!(offset, expected_offset);
            reconstructed[offset..offset + chunk.len()].copy_from_slice(chunk);
            expected_offset += chunk.len();
        }
        assert_eq!(expected_offset, proof.len());
        assert_eq!(reconstructed, proof);
    }
}

fn store_request(
    request: &IndexedRequest,
    fee_sats: u64,
    net_sats: u64,
    status: OperatorStatus,
) -> WithdrawalRequest {
    WithdrawalRequest {
        request_index: request.index,
        solana_signature: request.record.signature.to_string(),
        solana_slot: request.record.slot,
        block_time: request.record.block_time,
        user_pubkey: request.record.user_pubkey.to_string(),
        gross_amount_sats: request.record.amount_sats,
        fee_amount_sats: fee_sats,
        net_amount_sats: net_sats,
        address_type: request.record.address_type,
        recipient: request.record.recipient_address,
        status,
    }
}
