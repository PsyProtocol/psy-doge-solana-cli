use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use doge_bridge_client::{
    instructions, BridgeApi, BridgeClient, BridgeClientConfigBuilder, BridgeHistorySync,
    HistoryRecord, HistorySyncConfig, NoopShimMonitor, NoopShimMonitorConfig, OperatorApi,
    WithdrawalRequestRecord,
};
use doge_bridge_client::operator_store::{
    CustodyUtxo, CustodyUtxoStatus, DogecoinTransaction, OperatorStatus, OperatorStore,
    ProcessWithdrawal, WithdrawalRequest,
};
use doge_local_ops::{
    custody_ops,
    extract_vout_and_sats, plan_custody_transaction, tracked_utxo_spent_commitment,
    validate_decoded_custody_transaction, validate_proof_artifacts, CustodyTransactionPlan,
    TrackedSpentOutpoint, GROTH16_PROOF_SIZE, SATS_PER_DOGE,
};
use psy_bridge_core::crypto::hash::sha256_impl::hash_impl_sha256_bytes;
use psy_doge_solana_core::{
    program_state::PsyReturnTxOutput,
    utils::fees::calcuate_withdrawal_fee,
};
use reqwest::Client as HttpClient;
use serde::Serialize;
use serde_json::{json, Number, Value};
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
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::{process::Command, time::sleep};

const DEFAULT_DOGE_BRIDGE: &str = "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ";
const DEFAULT_PENDING_MINT: &str = "PMUSqycT1j5JTLmHk8frGSCido2h9VG1pyh2MPEa33o";
const DEFAULT_TXO_BUFFER: &str = "TXWhjswto9q6hfaGPuAhDS79wAHKfbMJLVR178xYAaQ";
const DEFAULT_GENERIC_BUFFER: &str = "GBYLmevzPSBPWfWrJ1h9gNzHqUjDXETzHKL1AasLyKwC";
const DEFAULT_MANUAL_CLAIM: &str = "MCdYbqiK3uj36tohbMjsh3Ssg8iRSJmSHToNxW8TWWE";
const DEFAULT_NOOP_SHIM: &str = "FwDChsHWLwbhTiYQ4Sum5mjVWswECi9cmrA11GUFUuxi";
const EXPECTED_WITHDRAWAL_VK: &str =
    "0x005ae8dd49562cce3ee0a2cc0cf405d3911e31ee97b56baaedc91092ed53ec6e";
const PROOF_FILENAME: &str = "withdrawal_groth16_proof.bin";
const PUBLIC_VALUES_FILENAME: &str = "withdrawal_public_values.bin";
const GENERIC_BUFFER_HEADER_SIZE: usize = 32;
const GENERIC_BUFFER_CHUNK_SIZE: usize = 900;
const PROCESS_COMPUTE_UNITS: u32 = 1_400_000;
const DUST_THRESHOLD_SATS: u64 = 10_000;

#[derive(Debug, Parser)]
#[command(
    name = "process-withdrawal",
    about = "Operator-side settlement of an existing Solana pDOGE burn onto Dogecoin regtest",
    long_about = "Reconstructs the selected request from Solana history, selects tracked bridge-custody UTXOs, constructs an exact Dogecoin transaction with recipient + change + fee, signs through Dogecoin Core wallet, broadcasts, computes spent-root transition from the local tracked-UTXO Merkle tree, invokes the real SP1 withdrawal prover, and submits process_withdrawal.",
    after_long_help = "CUSTODY:\n  Requires --operator-store with registered custody UTXOs (use deposit-to-solana). The spent-root is computed from the local tracked-UTXO sparse Merkle tree, not from a full canonical witness. The SP1 guest verifies the hash/public-value transition; it does not parse Dogecoin inputs/outputs or prove custody membership.\n\nSELECTION:\n  --request-index or --request-signature selects from Solana history. No recipient/amount overrides."
)]
struct Args {
    #[arg(long, conflicts_with = "request_signature", required_unless_present = "request_signature")]
    request_index: Option<u64>,
    #[arg(long, conflicts_with = "request_index", required_unless_present = "request_index")]
    request_signature: Option<Signature>,
    #[arg(long, required = true)]
    custody_address: String,
    #[arg(long)]
    change_address: Option<String>,
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
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    mine_blocks: u32,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    min_confirmations: u32,
    #[arg(long, default_value_t = 120)]
    confirmation_timeout_secs: u64,
    #[arg(long, default_value_t = 500)]
    poll_interval_ms: u64,
    #[arg(long, default_value = "../psy-bridge-sp1/target/release/gen-withdrawal-proof")]
    gen_withdrawal_proof_bin: PathBuf,
    #[arg(long, default_value = "/tmp/psy-bridge-withdrawal-proof")]
    proof_output_dir: PathBuf,
    #[arg(long)]
    operator_store: Option<PathBuf>,
    #[arg(long, default_value = "/tmp/doge-process-withdrawal-evidence.json")]
    evidence_path: PathBuf,
}

#[derive(Clone, Debug)]
struct IndexedRequest { index: u64, record: WithdrawalRequestRecord }
struct DogeRpc { client: HttpClient, url: String, user: String, password: String }

impl DogeRpc {
    fn new(url: String, user: String, password: String) -> Self { Self { client: HttpClient::new(), url, user, password } }
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let response = self.client.post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&json!({"jsonrpc":"1.0","id":"doge-local-withdrawal","method":method,"params":params}))
            .send().await.with_context(|| format!("call Dogecoin RPC {method}"))?;
        let status = response.status();
        let body: Value = response.json().await.with_context(|| format!("decode Dogecoin RPC {method} (HTTP {status})"))?;
        if !status.is_success() { bail!("Dogecoin RPC {method} returned HTTP {status}: {body}"); }
        if let Some(err) = body.get("error").filter(|v| !v.is_null()) { bail!("Dogecoin RPC {method} error: {err}"); }
        body.get("result").cloned().ok_or_else(|| anyhow!("Dogecoin RPC {method} missing result"))
    }
}

#[derive(Serialize)]
struct Evidence {
    schema: &'static str, completed: bool, mode: &'static str, limitations: Value,
    request: Value, snapshot: Value, dogecoin: Value, proof: Value,
    solana_process: Value, noop_shim: Value, operator_store: Value, custody: Value,
}

#[tokio::main]
async fn main() -> Result<()> { let args = Args::parse(); run(args).await }

async fn run(args: Args) -> Result<()> {
    let expected_bridge_state = Pubkey::find_program_address(&[doge_bridge_client::constants::BRIDGE_STATE_SEED], &args.doge_bridge_program).0;
    if let Some(provided) = args.bridge_state { if provided != expected_bridge_state { bail!("--bridge-state mismatch"); } }

    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;
    let client_config = BridgeClientConfigBuilder::new()
        .rpc_url(args.solana_rpc_url.clone()).bridge_state_pda(expected_bridge_state)
        .operator(clone_keypair(&operator)?).payer(clone_keypair(&payer)?)
        .program_id(args.doge_bridge_program).pending_mint_program_id(args.pending_mint_program)
        .txo_buffer_program_id(args.txo_buffer_program).generic_buffer_program_id(args.generic_buffer_program)
        .manual_claim_program_id(args.manual_claim_program)
        .wormhole_core_program_id(args.wormhole_core_program).wormhole_shim_program_id(args.wormhole_shim_program)
        .build().context("build bridge client")?;
    let bridge_client = BridgeClient::with_config(client_config)?;

    let mut store: Option<OperatorStore> = args.operator_store.as_ref().map(OperatorStore::open).transpose().context("open operator store")?;
    if store.is_none() { bail!("--operator-store is required for tracked custody UTXO mode"); }
    let store = store.as_mut().unwrap();

    let history = load_indexed_requests(&args, expected_bridge_state).await?;
    let selected = select_request(&history, args.request_index, args.request_signature.as_ref())?;
    let pre_snapshot = bridge_client.get_current_bridge_state().await?;
    ensure_next_unprocessed(&selected, pre_snapshot.next_processed_withdrawals_index)?;
    let fee = calcuate_withdrawal_fee(
        selected.record.amount_sats, pre_snapshot.config_params.withdrawal_flat_fee_sats,
        pre_snapshot.config_params.withdrawal_fee_rate_numerator, pre_snapshot.config_params.withdrawal_fee_rate_denominator,
    ).context("calculate fee")?;
    if fee.amount_after_fees == 0 || fee.fees_generated == 0 { bail!("invalid zero fee/net result"); }
    let recipient_address = dogecoin_regtest_address(selected.record.address_type, selected.record.recipient_address)?;

    store.upsert_withdrawal_request(&store_request(&selected, fee.fees_generated, fee.amount_after_fees, OperatorStatus::Observed))?;
    let snapshot_signature = bridge_client.execute_snapshot_withdrawals().await.context("snapshot_withdrawals")?;
    let state = bridge_client.get_current_bridge_state().await.context("read bridge state after snapshot")?;
    verify_snapshot(&state, &selected)?;
    store.upsert_withdrawal_request(&store_request(&selected, fee.fees_generated, fee.amount_after_fees, OperatorStatus::Snapshotted))?;

    let doge = DogeRpc::new(args.doge_rpc_url.clone(), args.doge_rpc_user.clone(), args.doge_rpc_password.clone());
    verify_regtest(&doge).await?;

    // ── Verify local spent root consistency with bridge state ──
    let all_utxos = store.list_custody_utxos().context("list all custody UTXOs")?;
    let spent_indices: Vec<u64> = all_utxos.iter()
        .filter(|u| u.status == CustodyUtxoStatus::Spent)
        .map(|u| u.leaf_index)
        .collect();
    let local_leaves = custody_ops::rebuild_merkle_leaves(&spent_indices);
    let local_root = if local_leaves.is_empty() {
        psy_bridge_core::crypto::hash::sha256::SHA256_ZERO_HASHES[
            psy_bridge_core::txo_constants::TXO_MERKLE_INDEX_TOTAL_BITS
        ]
    } else {
        custody_ops::compute_sparse_merkle_root(&local_leaves)
    };
    if local_root != state.spent_txo_tree_root {
        eprintln!(
            "warning: local spent tree root {} does not match bridge state root {}; bridge may have processed withdrawals outside this utility",
            hex::encode(local_root), hex::encode(state.spent_txo_tree_root)
        );
    }
    // ── Tracked custody UTXO selection ──
    let reservation_id = format!("withdrawal-{}", selected.index);
    let reservation = store.reserve_custody_utxos(&reservation_id, fee.amount_after_fees + args.fee_sats)
        .map_err(|e| anyhow!("custody UTXO reservation failed: {e}"))?;
    let selected_sats: u64 = reservation.utxos.iter().map(|u| u.amount_sats).sum();
    let reserved_utxos = reservation.utxos.clone();

    let plan = plan_custody_transaction(selected_sats, fee.amount_after_fees, args.fee_sats, args.dust_threshold_sats)
        .map_err(|e| { let _ = store.release_reservation(&reservation_id); e })?;

    // ── Raw transaction construction ──
    let amount_number = sats_to_doge_number(plan.recipient_sats)?;
    let change_address = args.change_address.as_ref();
    let mut output_map = serde_json::Map::new();
    output_map.insert(recipient_address.clone(), json!(amount_number));
    let change_number = if plan.change_sats != 0 {
        let addr = change_address.ok_or_else(|| {
            let _ = store.release_reservation(&reservation_id);
            anyhow!("change of {}-sat but no --change-address", plan.change_sats)
        })?;
        if *addr == recipient_address {
            let _ = store.release_reservation(&reservation_id);
            bail!("--change-address must differ from recipient");
        }
        let cn = sats_to_doge_number(plan.change_sats)?;
        output_map.insert(addr.clone(), json!(cn));
        Some(cn)
    } else { None };

    // Build inputs with reversed txid hex for Dogecoin Core RPC convention
    let inputs: Vec<Value> = reserved_utxos.iter().map(|utxo| {
        let mut txid_display = hex::encode(utxo.txid);
        // Reverse to get Dogecoin Core display order (little-endian hex)
        let txid_rev: String = txid_display.as_bytes().chunks(2).rev()
            .map(|c| unsafe { std::str::from_utf8_unchecked(c) }).collect();
        json!({"txid": txid_rev, "vout": utxo.vout})
    }).collect();

    let outputs = Value::Object(output_map);
    let unsigned_hex = doge.call("createrawtransaction", json!([inputs, outputs])).await?
        .as_str().ok_or_else(|| anyhow!("createrawtransaction result not hex"))?.to_owned();

    // ── Validate unsigned transaction ──
    let decoded = doge.call("decoderawtransaction", json!([unsigned_hex])).await?;
    let expected_input_refs: Vec<(String, u32)> = reserved_utxos.iter().map(|utxo| {
        let mut txid_display = hex::encode(utxo.txid);
        let txid_rev: String = txid_display.as_bytes().chunks(2).rev()
            .map(|c| unsafe { std::str::from_utf8_unchecked(c) }).collect();
        (txid_rev, utxo.vout)
    }).collect();
    validate_decoded_custody_transaction(&decoded, &expected_input_refs, &recipient_address,
        change_address.map(|s| s.as_str()), &plan, selected_sats)?;

    // ── Sign ──
    let sign_inputs: Vec<Value> = reserved_utxos.iter().map(|utxo| {
        let mut txid_display = hex::encode(utxo.txid);
        let txid_rev: String = txid_display.as_bytes().chunks(2).rev()
            .map(|c| unsafe { std::str::from_utf8_unchecked(c) }).collect();
        json!({"txid": txid_rev, "vout": utxo.vout, "scriptPubKey": utxo.script_pubkey_hex,
               "amount": sats_to_doge_json(utxo.amount_sats).unwrap_or(Value::Null)})
    }).collect();

    let signed = doge.call("signrawtransaction", json!([unsigned_hex, sign_inputs])).await?;
    if signed.get("complete").and_then(Value::as_bool) != Some(true) {
        let _ = store.release_reservation(&reservation_id);
        bail!("signrawtransaction incomplete: {:?}", signed.get("errors"));
    }
    let signed_hex = signed.get("hex").and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing signed hex"))?.to_owned();
    let signed_bytes = hex::decode(&signed_hex).context("decode signed tx")?;
    let raw_hash = hash_impl_sha256_bytes(&signed_bytes);

    store.upsert_dogecoin_transaction(&DogecoinTransaction {
        raw_hash, txid: None, raw_transaction: Some(signed_bytes.clone()),
        status: OperatorStatus::Signed, block_hash: None, block_height: None, confirmations: 0,
    })?;

    // ── Broadcast ──
    let txid_text = doge.call("sendrawtransaction", json!([signed_hex])).await?
        .as_str().ok_or_else(|| anyhow!("sendrawtransaction result not txid"))?.to_owned();
    let doge_txid = decode_displayed_hash32("Dogecoin txid", &txid_text)?;
    store.mark_reservation_broadcast(&reservation_id, &doge_txid)?;

    store.upsert_dogecoin_transaction(&DogecoinTransaction {
        raw_hash, txid: Some(doge_txid), raw_transaction: Some(signed_bytes.clone()),
        status: OperatorStatus::Broadcast, block_hash: None, block_height: None, confirmations: 0,
    })?;

    let mining_address = doge.call("getnewaddress", json!([])).await?
        .as_str().ok_or_else(|| anyhow!("getnewaddress failed"))?.to_owned();
    doge.call("generatetoaddress", json!([args.mine_blocks, mining_address])).await?;
    let verbose = wait_for_doge_confirmation(&doge, &txid_text, args.min_confirmations,
        Duration::from_secs(args.confirmation_timeout_secs), Duration::from_millis(args.poll_interval_ms)).await?;

    let (withdrawal_vout, paid_sats) = extract_vout_and_sats(&verbose, &recipient_address)?;
    if paid_sats != fee.amount_after_fees {
        bail!("confirmed payment {paid_sats} sats, expected {}", fee.amount_after_fees);
    }
    let raw_hex = doge.call("getrawtransaction", json!([txid_text, false])).await?
        .as_str().ok_or_else(|| anyhow!("getrawtransaction not hex"))?.to_owned();
    let raw_bytes = hex::decode(raw_hex).context("decode confirmed raw tx")?;
    if raw_bytes != signed_bytes { bail!("confirmed tx differs from signed bytes"); }
    let confirmations = verbose.get("confirmations").and_then(Value::as_u64).unwrap_or(0) as u32;
    let block_hash = verbose.get("blockhash").and_then(Value::as_str)
        .map(|v| decode_displayed_hash32("block hash", v)).transpose()?;
    let block_height = verbose.get("height").and_then(Value::as_u64).map(|h| h as u32);
    let tx_index_in_block = verbose.get("blockindex").and_then(Value::as_u64).unwrap_or(0) as u16;

    store.upsert_dogecoin_transaction(&DogecoinTransaction {
        raw_hash, txid: Some(doge_txid), raw_transaction: Some(raw_bytes.clone()),
        status: OperatorStatus::Confirmed, block_hash, block_height, confirmations,
    })?;

    let sighash = hash_impl_sha256_bytes(&raw_bytes);
    if sighash != raw_hash { bail!("raw tx hash changed after confirmation"); }

    // ── Compute spent-root transition ──
    let old_spent_root = state.spent_txo_tree_root;
    let spent_combined_indices: Vec<u64> = reserved_utxos.iter().map(|u| u.leaf_index).collect();
    let existing = custody_ops::rebuild_merkle_leaves(
        &store.list_custody_utxos().context("list all custody UTXOs")?.iter()
            .filter(|u| u.status == CustodyUtxoStatus::Spent)
            .map(|u| u.leaf_index)
            .collect::<Vec<_>>()
    );
    let leaf_updates = custody_ops::compute_updated_leaf_values(&spent_combined_indices, &existing);
    let new_spent_root = custody_ops::compute_sparse_merkle_root(
        &{ let mut all = existing; all.extend(leaf_updates); all }
    );

    // ── Register change output ──
    let change_utxo = if plan.change_sats != 0 {
        let addr = change_address.unwrap();
        let change_vout = verbose.get("vout").and_then(Value::as_array).and_then(|vouts|
            vouts.iter().position(|v| {
                let spk = v.get("scriptPubKey").unwrap_or(&Value::Null);
                spk.get("address").and_then(Value::as_str) == Some(addr)
                    || spk.get("addresses").and_then(Value::as_array)
                        .map(|addrs| addrs.iter().any(|a| a.as_str() == Some(addr))).unwrap_or(false)
            })
        ).map(|i| i as u32);

        match change_vout {
            Some(vout) => {
                let change_leaf = custody_ops::compute_combined_index(block_height.unwrap_or(0), tx_index_in_block, vout as u16);
                let change_spk = verbose.get("vout").and_then(Value::as_array)
                    .and_then(|vouts| vouts.iter().find(|v| v.get("n").and_then(Value::as_u64) == Some(vout as u64)))
                    .and_then(|v| v.get("scriptPubKey")).and_then(|spk| spk.get("hex")).and_then(Value::as_str)
                    .unwrap_or("").to_owned();
                Some(CustodyUtxo {
                    txid: doge_txid, vout, amount_sats: plan.change_sats,
                    script_pubkey_hex: change_spk, custody_address: addr.clone(),
                    key_reference: "bridge-custody-wallet#0".into(),
                    confirmation_block_hash: block_hash, confirmation_height: block_height,
                    confirmations, leaf_index: change_leaf, status: CustodyUtxoStatus::Available,
                    reservation_id: None, spend_txid: None,
                    source_deposit_txid: None, source_solana_signature: None,
                    spend_request_index: None, spend_process_signature: None,
                })
            }
            None => { eprintln!("warning: change output not located"); None }
        }
    } else { None };

    store.finalize_custody_spend(&reservation_id, change_utxo.as_ref().unwrap_or(&reserved_utxos[0]), &doge_txid)
        .map_err(|e| anyhow!("finalize custody spend failed: {e}"))?;

    // ── SP1 proof ──
    let new_return_output = if let Some(ref change) = change_utxo {
        PsyReturnTxOutput { sighash, output_index: change.vout as u64, amount_sats: change.amount_sats }
    } else {
        PsyReturnTxOutput { sighash, output_index: withdrawal_vout as u64, amount_sats: paid_sats }
    };

    let new_index = state.next_processed_withdrawals_index.checked_add(1)
        .ok_or_else(|| anyhow!("index overflow"))?;
    let expected_public_values = state.get_expected_public_inputs_for_withdrawal_proof(
        &new_return_output, new_spent_root, new_index,
    );
    let proof_path = args.proof_output_dir.join(PROOF_FILENAME);
    let pubvals_path = args.proof_output_dir.join(PUBLIC_VALUES_FILENAME);
    remove_stale(&proof_path)?; remove_stale(&pubvals_path)?;
    let prover_stdout = run_withdrawal_prover(&args, &state, &new_return_output, new_spent_root, new_index).await?;
    let (proof, public_values) = validate_withdrawal_artifacts(&proof_path, &pubvals_path, expected_public_values, &prover_stdout)?;

    // ── Solana process ──
    let solana_rpc = RpcClient::new_with_commitment(args.solana_rpc_url.clone(), CommitmentConfig::confirmed());
    let buffer = create_generic_buffer(&solana_rpc, &payer, args.generic_buffer_program, &raw_bytes).await?;
    let process_ix = instructions::process_withdrawal(
        args.doge_bridge_program, payer.pubkey(), buffer, args.wormhole_shim_program, args.wormhole_core_program,
        proof, new_return_output.clone(), new_spent_root, new_index,
    );

    // Pre-pay Wormhole fee: Core Bridge requires fee_collector to have received >= fee lamports
    // since the last post_message. Transfer 1000 lamports (fee is 10 on devnet) in the same tx.
    let (fee_collector_pda, _) = Pubkey::find_program_address(&[b"fee_collector"], &args.wormhole_core_program);
    let fee_prepay_ix = system_instruction::transfer(&payer.pubkey(), &fee_collector_pda, 1000);

    let process_signature = send_solana_transaction(&solana_rpc, &payer,
        &[ComputeBudgetInstruction::set_compute_unit_limit(PROCESS_COMPUTE_UNITS), fee_prepay_ix, process_ix], &[],
    ).await.context("submit process_withdrawal")?;

    let process_sig_str = process_signature.to_string();
    store.link_reservation_to_withdrawal(&reservation_id, Some(selected.index), Some(process_sig_str.as_str()))?;

    let post_state = bridge_client.get_current_bridge_state().await.context("read post-process state")?;
    if post_state.next_processed_withdrawals_index != new_index
        || post_state.last_return_output.sighash != sighash
        || post_state.last_return_output.output_index != new_return_output.output_index
        || post_state.last_return_output.amount_sats != new_return_output.amount_sats
        || post_state.spent_txo_tree_root != new_spent_root
    { bail!("process_withdrawal did not produce expected bridge state transition"); }

    // ── Noop shim verification ──
    let monitor = NoopShimMonitor::new(
        NoopShimMonitorConfig::new(args.solana_rpc_url.clone(), expected_bridge_state)
            .noop_shim_program_id(args.wormhole_shim_program).batch_size(50),
    )?;
    let noop = find_noop_message(&monitor, &process_signature).await?;
    if noop.emitter != expected_bridge_state { bail!("noop emitter mismatch"); }
    if noop.payer != payer.pubkey() { bail!("noop payer mismatch"); }
    if noop.consistency_level != 1 { bail!("noop consistency level {}", noop.consistency_level); }
    if noop.sighash != sighash { bail!("noop sighash mismatch"); }
    if noop.doge_tx_bytes != raw_bytes { bail!("noop doge_tx_bytes mismatch"); }

    let process_meta = solana_rpc.get_transaction(&process_signature, UiTransactionEncoding::Base64).await
        .context("fetch process transaction")?;

    store.upsert_process_withdrawal(&ProcessWithdrawal {
        solana_signature: process_signature.to_string(), solana_slot: process_meta.slot,
        block_time: process_meta.block_time, request_start_index: selected.index,
        request_end_index: selected.index + 1,
        snapshot_root: state.withdrawal_snapshot.requested_withdrawals_tree_root,
        dogecoin_raw_hash: raw_hash, return_output_index: new_return_output.output_index,
        return_output_amount_sats: new_return_output.amount_sats,
        old_spent_txo_root: old_spent_root, new_spent_txo_root: new_spent_root,
        status: OperatorStatus::Confirmed,
    })?;
    store.map_process_range_to_txid(&process_signature.to_string(), &doge_txid)?;
    store.set_withdrawal_request_status(selected.index, OperatorStatus::Confirmed)?;

    let evidence = Evidence {
        schema: "doge-local-process-withdrawal-v2", completed: true, mode: "tracked-custody",
        limitations: json!({
            "bridge_owned_utxo_selection": true,
            "spent_root_witness_available": true,
            "spent_root_source": "local-tracked-utxo-merkle-tree",
            "spent_root_new_hex": hex::encode(new_spent_root),
            "semantic_prover_limit": "SP1 proves the current hash/public-value transition; it does not parse or semantically validate Dogecoin inputs, outputs, custody, inclusion, or spent-UTXO membership",
            "guardian_release": false,
        }),
        request: json!({ "index": selected.index, "burn_signature": selected.record.signature.to_string(), "slot": selected.record.slot, "user": selected.record.user_pubkey.to_string(), "gross_amount_sats": selected.record.amount_sats, "fee_amount_sats": fee.fees_generated, "net_amount_sats": fee.amount_after_fees, "address_type": selected.record.address_type, "recipient_payload_hex": hex::encode(selected.record.recipient_address), "recipient_regtest_address": recipient_address, "authoritative_source": "Solana history; no overrides" }),
        snapshot: json!({ "signature": snapshot_signature.to_string(), "hash_hex": hex::encode(state.withdrawal_snapshot.get_hash()), "requested_root_hex": hex::encode(state.withdrawal_snapshot.requested_withdrawals_tree_root), "request_end_index": state.withdrawal_snapshot.next_requested_withdrawals_tree_index }),
        dogecoin: json!({ "txid": txid_text, "raw_single_sha256_hex": hex::encode(raw_hash), "raw_bytes": raw_bytes.len(), "recipient_vout": withdrawal_vout, "recipient_sats": paid_sats, "change_sats": plan.change_sats, "fee_sats": args.fee_sats, "confirmations": confirmations }),
        proof: json!({ "system": "SP1 v6 Groth16", "mock_zkp": false, "proof_path": proof_path, "proof_bytes": GROTH16_PROOF_SIZE, "proof_sha256_hex": hex::encode(Sha256::digest(proof)), "public_values_path": pubvals_path, "public_values_hex": hex::encode(public_values), "withdrawal_vk": EXPECTED_WITHDRAWAL_VK }),
        solana_process: json!({ "signature": process_signature.to_string(), "slot": process_meta.slot, "compute_unit_limit": PROCESS_COMPUTE_UNITS, "generic_buffer": buffer.to_string(), "new_processed_index": new_index, "old_spent_root_hex": hex::encode(old_spent_root), "new_spent_root_hex": hex::encode(new_spent_root) }),
        noop_shim: json!({ "verified": true, "signature": noop.signature.to_string(), "emitter": noop.emitter.to_string(), "payer": noop.payer.to_string(), "sighash_hex": hex::encode(noop.sighash), "doge_tx_bytes": noop.doge_tx_bytes.len() }),
        operator_store: json!({ "enabled": true, "path": args.operator_store, "linkage": "burn <-> Dogecoin txid <-> process <-> custody persisted" }),
        custody: json!({ "reservation_id": reservation_id, "selected_utxos": reserved_utxos.iter().map(|u| json!({"txid": hex::encode(u.txid), "vout": u.vout, "sats": u.amount_sats, "leaf_index": u.leaf_index.to_string()})).collect::<Vec<_>>(), "selected_total_sats": selected_sats, "change_sats": plan.change_sats, "change_registered": change_utxo.is_some(), "spent_leaf_indices": spent_combined_indices.iter().map(|ci| ci.to_string()).collect::<Vec<_>>() }),
    };
    if let Some(parent) = args.evidence_path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(&args.evidence_path, serde_json::to_vec_pretty(&evidence)?)
        .with_context(|| format!("write {}", args.evidence_path.display()))?;
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

fn read_keypair(path: &Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path).map_err(|e| anyhow!("read {role} keypair: {e}"))
}
fn clone_keypair(k: &Keypair) -> Result<Keypair> { Keypair::from_bytes(&k.to_bytes()).context("clone keypair") }

async fn load_indexed_requests(args: &Args, bridge_state: Pubkey) -> Result<Vec<IndexedRequest>> {
    let config = HistorySyncConfig::new(args.solana_rpc_url.clone(), args.doge_bridge_program, bridge_state, args.pending_mint_program, args.txo_buffer_program)
        .include_withdrawals(true).include_manual_deposits(false);
    let sync = BridgeHistorySync::new(config)?;
    let (mut rx, mut handle) = sync.stream_history(None).await?;
    let mut requests = Vec::new();
    while let Some(record) = rx.recv().await { if let HistoryRecord::WithdrawalRequest(record) = record { requests.push(record); } }
    handle.join().await.context("join history sync")?;
    requests.sort_by_key(|r| r.slot);
    Ok(requests.into_iter().enumerate().map(|(i, r)| IndexedRequest { index: i as u64, record: r }).collect())
}

fn select_request(requests: &[IndexedRequest], idx: Option<u64>, sig: Option<&Signature>) -> Result<IndexedRequest> {
    match (idx, sig) {
        (Some(i), None) => requests.iter().find(|r| r.index == i),
        (None, Some(s)) => requests.iter().find(|r| r.record.signature == *s),
        _ => bail!("provide exactly one of --request-index or --request-signature"),
    }.cloned().ok_or_else(|| anyhow!("request not found in Solana history"))
}

fn ensure_next_unprocessed(request: &IndexedRequest, next: u64) -> Result<()> {
    if request.index != next { bail!("request index {} != next unprocessed {next}", request.index); }
    Ok(())
}

fn verify_snapshot(state: &doge_bridge_client::PsyBridgeProgramState, request: &IndexedRequest) -> Result<()> {
    let snap = state.withdrawal_snapshot;
    if request.index >= snap.next_requested_withdrawals_tree_index { bail!("request not in snapshot"); }
    if snap.requested_withdrawals_tree_root != state.requested_withdrawals_tree.get_root() { bail!("snapshot root mismatch"); }
    if snap.next_requested_withdrawals_tree_index != state.requested_withdrawals_tree.next_index { bail!("snapshot index mismatch"); }
    Ok(())
}

fn dogecoin_regtest_address(at: u32, payload: [u8; 20]) -> Result<String> {
    let version = match at { 0 => 0x6f, 1 => 0xc4, other => bail!("unsupported address type {other}") };
    let mut bytes = Vec::with_capacity(21); bytes.push(version); bytes.extend_from_slice(&payload);
    Ok(bs58::encode(bytes).with_check().into_string())
}

fn sats_to_doge_number(sats: u64) -> Result<Number> {
    let whole = sats / SATS_PER_DOGE;
    let fraction = sats % SATS_PER_DOGE;
    let text = if fraction == 0 { whole.to_string() } else {
        let mut v = format!("{whole}.{fraction:08}");
        while v.ends_with('0') { v.pop(); }
        v
    };
    Number::from_str(&text).with_context(|| format!("encode {sats} sats"))
}

fn sats_to_doge_json(sats: u64) -> Result<Value> {
    serde_json::from_str(&format!("{}.{:08}", sats / SATS_PER_DOGE, sats % SATS_PER_DOGE))
        .with_context(|| format!("encode {sats} sats as JSON"))
}

async fn verify_regtest(rpc: &DogeRpc) -> Result<()> {
    let chain = rpc.call("getblockchaininfo", json!([])).await?
        .get("chain").and_then(Value::as_str).map(str::to_owned)
        .ok_or_else(|| anyhow!("getblockchaininfo missing chain"))?;
    if chain != "regtest" { bail!("refusing chain {chain}"); }
    Ok(())
}

async fn wait_for_doge_confirmation(rpc: &DogeRpc, txid: &str, minimum: u32, timeout: Duration, interval: Duration) -> Result<Value> {
    let start = Instant::now();
    loop {
        let v = rpc.call("getrawtransaction", json!([txid, true])).await?;
        let c = v.get("confirmations").and_then(Value::as_u64).unwrap_or(0);
        if c >= minimum as u64 { return Ok(v); }
        if start.elapsed() >= timeout { bail!("tx {txid} has {c} confirmations after {}s", timeout.as_secs()); }
        sleep(interval).await;
    }
}

async fn run_withdrawal_prover(args: &Args, state: &doge_bridge_client::PsyBridgeProgramState, new_return: &PsyReturnTxOutput, new_spent_root: [u8; 32], new_index: u64) -> Result<String> {
    std::fs::create_dir_all(&args.proof_output_dir)?;
    let output = Command::new(&args.gen_withdrawal_proof_bin)
        .arg("--snapshot-hash").arg(hex::encode(state.withdrawal_snapshot.get_hash()))
        .arg("--old-return-output-bytes").arg(hex::encode(bytemuck::bytes_of(&state.last_return_output)))
        .arg("--new-return-output-bytes").arg(hex::encode(bytemuck::bytes_of(new_return)))
        .arg("--old-spent-root").arg(hex::encode(state.spent_txo_tree_root))
        .arg("--new-spent-root").arg(hex::encode(new_spent_root))
        .arg("--custodian-hash").arg(hex::encode(state.custodian_wallet_config_hash))
        .arg("--new-index-u64").arg(new_index.to_string())
        .arg("--output-dir").arg(&args.proof_output_dir)
        .output().await.with_context(|| format!("run prover {}", args.gen_withdrawal_proof_bin.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() { bail!("prover failed: {}\n{stdout}\n{stderr}", output.status); }
    Ok(format!("{stdout}\n{stderr}"))
}

fn validate_withdrawal_artifacts(proof_path: &Path, pubvals_path: &Path, expected: [u8; 32], output: &str) -> Result<([u8; GROTH16_PROOF_SIZE], [u8; 32])> {
    let (proof, pubvals) = validate_proof_artifacts(proof_path, pubvals_path)?;
    if proof.len() != GROTH16_PROOF_SIZE { bail!("proof must be exactly {GROTH16_PROOF_SIZE} bytes"); }
    if proof.iter().all(|b| *b == 0) { bail!("proof is all zeros"); }
    if pubvals != expected { bail!("public values mismatch"); }
    if !output.to_ascii_lowercase().contains(&EXPECTED_WITHDRAWAL_VK.to_ascii_lowercase()) { bail!("prover output missing VK"); }
    Ok((proof, pubvals))
}

fn remove_stale(path: &Path) -> Result<()> { if path.exists() { std::fs::remove_file(path)?; } Ok(()) }

async fn create_generic_buffer(rpc: &RpcClient, payer: &Keypair, program_id: Pubkey, data: &[u8]) -> Result<Pubkey> {
    let account = Keypair::new();
    let rent = rpc.get_minimum_balance_for_rent_exemption(GENERIC_BUFFER_HEADER_SIZE).await?;
    let create = system_instruction::create_account(&payer.pubkey(), &account.pubkey(), rent, GENERIC_BUFFER_HEADER_SIZE as u64, &program_id);
    let init = instructions::generic_buffer_init(program_id, account.pubkey(), payer.pubkey(), data.len() as u32);
    send_solana_transaction(rpc, payer, &[create, init], &[&account]).await?;
    for (i, chunk) in data.chunks(GENERIC_BUFFER_CHUNK_SIZE).enumerate() {
        let write = instructions::generic_buffer_write(program_id, account.pubkey(), payer.pubkey(), (i * GENERIC_BUFFER_CHUNK_SIZE) as u32, chunk);
        send_solana_transaction(rpc, payer, &[write], &[]).await?;
    }
    Ok(account.pubkey())
}

async fn send_solana_transaction(rpc: &RpcClient, payer: &Keypair, instructions: &[solana_sdk::instruction::Instruction], extra: &[&Keypair]) -> Result<Signature> {
    let blockhash = rpc.get_latest_blockhash().await?;
    let mut signers = vec![payer]; signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(instructions, Some(&payer.pubkey()), &signers, blockhash);
    rpc.send_and_confirm_transaction(&tx).await.map_err(Into::into)
}

async fn find_noop_message(monitor: &NoopShimMonitor, sig: &Signature) -> Result<doge_bridge_client::NoopShimWithdrawalMessage> {
    let mut before = None;
    for _ in 0..10 {
        let page = monitor.get_withdrawals(before, 50).await?;
        if let Some(msg) = page.messages.into_iter().find(|m| m.signature == *sig) { return Ok(msg); }
        if !page.has_more { break; } before = page.next_cursor;
    }
    bail!("process signature {sig} not found in noop history")
}

fn decode_displayed_hash32(name: &str, text: &str) -> Result<[u8; 32]> {
    let mut bytes = hex::decode(text).with_context(|| format!("decode {name}"))?;
    if bytes.len() != 32 { bail!("{name} must be 32 bytes"); }
    bytes.reverse();
    Ok(bytes.try_into().expect("32"))
}

fn store_request(request: &IndexedRequest, fee_sats: u64, net_sats: u64, status: OperatorStatus) -> WithdrawalRequest {
    WithdrawalRequest {
        request_index: request.index, solana_signature: request.record.signature.to_string(),
        solana_slot: request.record.slot, block_time: request.record.block_time,
        user_pubkey: request.record.user_pubkey.to_string(), gross_amount_sats: request.record.amount_sats,
        fee_amount_sats: fee_sats, net_amount_sats: net_sats, address_type: request.record.address_type,
        recipient: request.record.recipient_address, status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(byte: u8, amount: u64, at: u32) -> WithdrawalRequestRecord {
        WithdrawalRequestRecord {
            signature: Signature::new_unique(), slot: byte as u64, block_time: None,
            amount_sats: amount, recipient_address: [byte; 20], address_type: at,
            user_pubkey: Keypair::new().pubkey(),
        }
    }
    #[test] fn converts_regtest_addresses() {
        let p2pkh = dogecoin_regtest_address(0, [5u8; 20]).unwrap();
        let p2sh = dogecoin_regtest_address(1, [5u8; 20]).unwrap();
        assert!(dogecoin_regtest_address(2, [5u8; 20]).is_err());
        assert!(bs58::decode(&p2pkh).with_check(None).into_vec().is_ok());
        assert!(bs58::decode(&p2sh).with_check(None).into_vec().is_ok());
    }
    #[test] fn selects_request_by_index_or_signature() {
        let a = IndexedRequest { index: 0, record: record(1, 100, 0) };
        let b = IndexedRequest { index: 1, record: record(2, 200, 1) };
        assert_eq!(select_request(&[a.clone(), b.clone()], Some(1), None).unwrap().record.amount_sats, 200);
        assert_eq!(select_request(&[a.clone(), b.clone()], None, Some(&a.record.signature)).unwrap().index, 0);
        assert!(select_request(&[a, b], Some(0), Some(&Signature::new_unique())).is_err());
    }
    #[test] fn validates_artifact_lengths() {
        let mut proof = [7u8; GROTH16_PROOF_SIZE]; let pv = [3u8; 32];
        let output = format!("vk_hash: {EXPECTED_WITHDRAWAL_VK}");
        validate_withdrawal_artifacts_inner(&proof, &pv, pv, &output).unwrap();
        proof.fill(0);
        assert!(validate_withdrawal_artifacts_inner(&proof, &pv, pv, &output).is_err());
    }
    fn validate_withdrawal_artifacts_inner(proof: &[u8], pubvals: &[u8], expected: [u8; 32], output: &str) -> Result<()> {
        if proof.len() != GROTH16_PROOF_SIZE { bail!("size") }
        if proof.iter().all(|b| *b == 0) { bail!("zero") }
        if pubvals != expected { bail!("values") }
        if !output.to_ascii_lowercase().contains(&EXPECTED_WITHDRAWAL_VK.to_ascii_lowercase()) { bail!("vk") }
        Ok(())
    }
    #[test] fn enforces_queue_order() {
        assert!(ensure_next_unprocessed(&IndexedRequest { index: 4, record: record(4, 100, 0) }, 3).is_err());
        assert!(ensure_next_unprocessed(&IndexedRequest { index: 4, record: record(4, 100, 0) }, 4).is_ok());
    }
    #[test] fn exact_satoshi_decimal() {
        assert_eq!(sats_to_doge_number(39_199_000).unwrap().to_string(), "0.39199");
        assert_eq!(sats_to_doge_number(100_000_000).unwrap().to_string(), "1");
        assert_eq!(sats_to_doge_number(1).unwrap().to_string(), "0.00000001");
    }
}
