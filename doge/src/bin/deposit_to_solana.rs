use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use doge_bridge_client::{
    instructions, BridgeApi, BridgeClient, BridgeClientConfigBuilder, PendingMint,
    PsyBridgeTipStateCommitment,
};
use doge_bridge_client::operator_store::{
    CustodyUtxo, CustodyUtxoStatus, OperatorStore,
};
use doge_local_ops::{
    custody_ops, doge_amount_to_sats, extract_vout_and_sats, validate_proof_artifacts,
    BLOCK_PUBLIC_VALUES_SIZE, GROTH16_PROOF_SIZE, SATS_PER_DOGE,
};
use psy_bridge_core::crypto::hash::sha256_impl::hash_impl_sha256_bytes;
use psy_bridge_core::txo_constants::get_txo_combined_index;
use psy_doge_solana_core::{
    data_accounts::pending_mint::{
        PM_DA_DEFAULT_PENDING_MINTS_BUFFER_HASH, PM_MAX_PENDING_MINTS_PER_GROUP,
        PM_TXO_DEFAULT_BUFFER_HASH,
    },
    public_inputs::get_block_transition_public_inputs,
};
use reqwest::Client as HttpClient;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    transaction::Transaction,
};
use std::{
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
const DEFAULT_PROOF_PATH: &str = "/tmp/bridge-block-transition-proof.bin";
const DEFAULT_PUBLIC_VALUES_PATH: &str = "/tmp/bridge-block-transition-pubvals.bin";
const DEFAULT_CUSTODY_KEY_REFERENCE: &str = "bridge-custody-wallet#0";

#[derive(Debug, Parser)]
#[command(
    name = "deposit-to-solana",
    about = "One-shot local-regtest Dogecoin deposit to the real-SP1 Solana bridge",
    long_about = "Create or use a Dogecoin regtest address, send and mine a deposit, stage the bridge pending-mint/TXO buffers, invoke the existing psy-bridge-sp1 gen-proof binary, submit a 1,400,000-CU block_update, process mint groups, and write JSON evidence. Optionally registers the confirmed deposit output as a tracked custody UTXO.",
    after_long_help = "LIMITATIONS:\n  This operator utility is for a trusted local Dogecoin regtest plus local Solana validator only. It reproduces the currently verified real-E2E transition semantics: the deposit vout is used as the TXO index and the next tip commitment uses synthetic [1;32] block hash/root and +60 seconds. The SP1 block-transition guest proves the agreed header/config/custodian hash formula; it does not parse Dogecoin consensus, prove transaction inclusion, bind the recipient to a Dogecoin deposit script, maintain a canonical bridge UTXO database, or establish mainnet finality. The caller must supply the correct recipient pDOGE token account. A 356-byte proof is necessary but is not by itself evidence that a proof is non-mock; use a gen-p…"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    solana_rpc_url: String,
    #[arg(long)]
    operator_keypair: PathBuf,
    #[arg(long)]
    payer_keypair: PathBuf,
    #[arg(long)]
    recipient_token_account: Pubkey,
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
    #[arg(long)]
    bridge_state: Option<Pubkey>,
    #[arg(long, default_value = "http://127.0.0.1:22555")]
    doge_rpc_url: String,
    #[arg(long, default_value = "doge")]
    doge_rpc_user: String,
    #[arg(long, default_value = "doge")]
    doge_rpc_password: String,
    #[arg(long)]
    deposit_address: Option<String>,
    #[arg(long, default_value_t = SATS_PER_DOGE)]
    amount_sats: u64,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    mine_blocks: u32,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
    min_confirmations: u64,
    #[arg(long, default_value_t = 120)]
    confirmation_timeout_secs: u64,
    #[arg(long, default_value_t = 500)]
    poll_interval_ms: u64,
    #[arg(long)]
    gen_proof_bin: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_PROOF_PATH)]
    proof_path: PathBuf,
    #[arg(long, default_value = DEFAULT_PUBLIC_VALUES_PATH)]
    public_values_path: PathBuf,
    #[arg(long, default_value = DEFAULT_CUSTODY_KEY_REFERENCE)]
    custody_key_reference: String,
    #[arg(long)]
    operator_store: Option<PathBuf>,
    #[arg(long, default_value = "/tmp/doge-deposit-to-solana-evidence.json")]
    evidence_path: PathBuf,
}

struct DogeRpc {
    client: HttpClient,
    url: String,
    user: String,
    password: String,
}

impl DogeRpc {
    fn new(url: String, user: String, password: String) -> Self {
        Self { client: HttpClient::new(), url, user, password }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let response = self.client.post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&json!({"jsonrpc":"1.0","id":"doge-local-deposit","method":method,"params":params}))
            .send().await.with_context(|| format!("call Dogecoin RPC {method} at {}", self.url))?;
        let status = response.status();
        let body: Value = response.json().await
            .with_context(|| format!("decode Dogecoin RPC {method} response (HTTP {status})"))?;
        if !status.is_success() { bail!("Dogecoin RPC {method} returned HTTP {status}: {body}"); }
        if let Some(error) = body.get("error").filter(|error| !error.is_null()) {
            bail!("Dogecoin RPC {method} error: {error}");
        }
        body.get("result").cloned()
            .ok_or_else(|| anyhow!("Dogecoin RPC {method} response missing result"))
    }
}

#[derive(Serialize)]
struct Limitations {
    environment: &'static str,
    transition_semantics: &'static str,
    guest_semantics: &'static str,
    recipient_binding: &'static str,
    proof_warning: &'static str,
    guardian_status: &'static str,
}

#[derive(Serialize)]
struct Evidence {
    schema: &'static str,
    completed: bool,
    proof_system: &'static str,
    mock_zkp_requested: bool,
    limitations: Limitations,
    dogecoin: Value,
    solana: Value,
    buffers: Value,
    block_transition: Value,
    mint_processing: Value,
    operator_store: Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    run(args).await
}

async fn run(args: Args) -> Result<()> {
    if args.amount_sats == 0 { bail!("--amount-sats must be greater than zero"); }
    if args.min_confirmations > args.mine_blocks as u64 {
        bail!("--min-confirmations ({}) exceeds --mine-blocks ({}); mine enough blocks", args.min_confirmations, args.mine_blocks);
    }
    let gen_proof_bin = args.gen_proof_bin.clone().unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../psy-bridge-sp1/target/release/gen-proof")
    });
    if !gen_proof_bin.is_file() {
        bail!("gen-proof binary not found at {}. Build the sibling psy-bridge-sp1 script binary first", gen_proof_bin.display());
    }

    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;
    let (derived_bridge_state, _) = Pubkey::find_program_address(&[b"bridge_state"], &args.doge_bridge_program);
    if let Some(provided) = args.bridge_state {
        if provided != derived_bridge_state {
            bail!("--bridge-state {provided} does not match derived PDA {derived_bridge_state}");
        }
    }

    // Open the operator store for custody UTXO registration
    let store = args.operator_store.as_ref().map(|path| {
        OperatorStore::open(path).context("open operator store")
    }).transpose()?;

    let client_config = BridgeClientConfigBuilder::new()
        .rpc_url(args.solana_rpc_url.clone())
        .bridge_state_pda(derived_bridge_state)
        .operator(clone_keypair(&operator)?)
        .payer(clone_keypair(&payer)?)
        .program_id(args.doge_bridge_program)
        .pending_mint_program_id(args.pending_mint_program)
        .txo_buffer_program_id(args.txo_buffer_program)
        .generic_buffer_program_id(args.generic_buffer_program)
        .manual_claim_program_id(args.manual_claim_program)
        .wormhole_core_program_id(args.noop_shim_program)
        .wormhole_shim_program_id(args.noop_shim_program)
        .build().context("build bridge client configuration")?;
    let bridge_client = BridgeClient::with_config(client_config).context("create bridge client")?;
    let pre_state = bridge_client.get_current_bridge_state().await.context("read initialized bridge state")?;

    let doge = DogeRpc::new(args.doge_rpc_url.clone(), args.doge_rpc_user.clone(), args.doge_rpc_password.clone());
    assert_regtest(&doge).await?;
    let deposit_address = match args.deposit_address.clone() {
        Some(address) => {
            doge.call("validateaddress", json!([address.clone()])).await
                .context("validate supplied deposit address")?
                .get("isvalid").and_then(Value::as_bool).filter(|valid| *valid)
                .ok_or_else(|| anyhow!("--deposit-address is not valid"))?;
            address
        }
        None => doge.call("getnewaddress", json!([])).await?
            .as_str().ok_or_else(|| anyhow!("getnewaddress did not return a string"))?.to_owned(),
    };

    let deposit_amount = sats_to_doge_json(args.amount_sats)?;
    let txid = doge.call("sendtoaddress", json!([deposit_address.clone(), deposit_amount])).await?
        .as_str().ok_or_else(|| anyhow!("sendtoaddress did not return a txid string"))?.to_owned();
    let mining_address = doge.call("getnewaddress", json!([])).await?
        .as_str().ok_or_else(|| anyhow!("mining getnewaddress did not return a string"))?.to_owned();
    doge.call("generatetoaddress", json!([args.mine_blocks, mining_address])).await
        .context("mine Dogecoin deposit")?;
    let verbose = poll_deposit(&doge, &txid, args.min_confirmations,
        Duration::from_secs(args.confirmation_timeout_secs), Duration::from_millis(args.poll_interval_ms)).await?;
    let confirmations = verbose.get("confirmations").and_then(Value::as_u64).unwrap_or_default();
    let (deposit_vout, deposit_sats) = extract_vout_and_sats(&verbose, &deposit_address)?;
    if deposit_sats != args.amount_sats {
        bail!("mined deposit output amount mismatch: requested {} sats, found {} sats", args.amount_sats, deposit_sats);
    }

    // ── Compute combined index and register custody UTXO ──
    let block_height = verbose.get("height").and_then(Value::as_u64).unwrap_or(0) as u32;
    let tx_index = verbose.get("blockindex").and_then(Value::as_u64).unwrap_or(0) as u16;
    let leaf_index = custody_ops::compute_combined_index(block_height, tx_index, deposit_vout as u16);

    let block_hash = verbose.get("blockhash").and_then(Value::as_str)
        .and_then(|h| {
            let mut b = [0u8; 32];
            hex::decode_to_slice(h, &mut b).ok().map(|_| { b.reverse(); b })
        });

    let mut txid_bytes = [0u8; 32];
    let raw_txid = hex::decode(&txid).context("decode deposit txid hex")?;
    if raw_txid.len() == 32 {
        let mut rev = raw_txid;
        rev.reverse();
        txid_bytes = rev.try_into().expect("32 bytes");
    } else {
        txid_bytes.copy_from_slice(&raw_txid);
    }

    let script_pubkey_hex = verbose.get("vout").and_then(Value::as_array)
        .and_then(|vouts| vouts.iter().find(|v| v.get("n").and_then(Value::as_u64) == Some(deposit_vout as u64)))
        .and_then(|v| v.get("scriptPubKey")).and_then(|spk| spk.get("hex")).and_then(Value::as_str)
        .unwrap_or("").to_owned();

    if let Some(ref store) = store {
        let utxo = CustodyUtxo {
            txid: txid_bytes,
            vout: deposit_vout,
            amount_sats: deposit_sats,
            script_pubkey_hex,
            custody_address: deposit_address.clone(),
            key_reference: args.custody_key_reference.clone(),
            confirmation_block_hash: block_hash,
            confirmation_height: Some(block_height),
            confirmations: confirmations as u32,
            leaf_index,
            status: CustodyUtxoStatus::Available,
            reservation_id: None,
            spend_txid: None,
            source_deposit_txid: Some(txid_bytes),
            source_solana_signature: None,
            spend_request_index: None,
            spend_process_signature: None,
        };
        store.upsert_custody_utxo(&utxo).context("register deposit custody UTXO")?;
    }

    // ── Continue with existing deposit flow ──
    let pending_mints = vec![PendingMint { recipient: args.recipient_token_account.to_bytes(), amount: deposit_sats }];
    let txo_indices = vec![deposit_vout];
    let pending_mints_hash = compute_mints_hash(&pending_mints);
    let txo_hash = compute_txo_hash(&txo_indices);

    let old_header = pre_state.bridge_header;
    let mut new_header = old_header;
    new_header.finalized_state.block_height = new_header.finalized_state.block_height.checked_add(1)
        .ok_or_else(|| anyhow!("finalized block height overflow"))?;
    new_header.finalized_state.pending_mints_finalized_hash = pending_mints_hash;
    new_header.finalized_state.txo_output_list_finalized_hash = txo_hash;
    new_header.finalized_state.auto_claimed_deposits_next_index = new_header.finalized_state.auto_claimed_deposits_next_index
        .checked_add(pending_mints.len() as u32).ok_or_else(|| anyhow!("deposit index overflow"))?;
    new_header.tip_state = PsyBridgeTipStateCommitment {
        block_hash: [1u8; 32], block_merkle_tree_root: [1u8; 32],
        block_time: old_header.tip_state.block_time.checked_add(60).ok_or_else(|| anyhow!("tip block time overflow"))?,
        block_height: old_header.tip_state.block_height.checked_add(1).ok_or_else(|| anyhow!("tip block height overflow"))?,
    };

    let old_header_bytes = bytemuck::bytes_of(&old_header);
    let new_header_bytes = bytemuck::bytes_of(&new_header);
    let config_bytes = bytemuck::bytes_of(&pre_state.config_params);

    remove_stale_artifact(&args.proof_path)?;
    remove_stale_artifact(&args.public_values_path)?;
    let prover_output = invoke_gen_proof(&gen_proof_bin, old_header_bytes, new_header_bytes, config_bytes, &pre_state.custodian_wallet_config_hash).await?;
    let (proof, public_values) = validate_proof_artifacts(&args.proof_path, &args.public_values_path)?;
    let expected_public_values = get_block_transition_public_inputs(
        &old_header.get_hash_canonical(), &new_header.get_hash_canonical(),
        &pre_state.config_params.get_hash(), &pre_state.custodian_wallet_config_hash,
    );
    if public_values != expected_public_values {
        bail!("gen-proof public values do not match the bridge's expected block-transition inputs");
    }

    let new_height = new_header.finalized_state.block_height;
    let (mint_buffer, mint_bump) = bridge_client.setup_pending_mints_buffer(new_height, &pending_mints).await.context("stage pending-mint buffer")?;
    let (txo_buffer, txo_bump) = bridge_client.setup_txo_buffer(new_height, &txo_indices).await.context("stage TXO buffer")?;

    let block_update_ix = instructions::block_update(args.doge_bridge_program, payer.pubkey(), proof, new_header, operator.pubkey(), mint_buffer, txo_buffer, mint_bump, txo_bump);
    let solana_rpc = RpcClient::new_with_commitment(args.solana_rpc_url.clone(), CommitmentConfig::confirmed());
    let recent_blockhash = solana_rpc.get_latest_blockhash().await.context("get Solana blockhash")?;
    let block_update_tx = if payer.pubkey() == operator.pubkey() {
        Transaction::new_signed_with_payer(&[ComputeBudgetInstruction::set_compute_unit_limit(1_400_000), block_update_ix], Some(&payer.pubkey()), &[&payer], recent_blockhash)
    } else {
        Transaction::new_signed_with_payer(&[ComputeBudgetInstruction::set_compute_unit_limit(1_400_000), block_update_ix], Some(&payer.pubkey()), &[&payer, &operator], recent_blockhash)
    };
    let block_update_signature = solana_rpc.send_and_confirm_transaction(&block_update_tx).await.context("submit real-SP1 block_update")?;
    let mint_result = bridge_client.process_remaining_pending_mints_groups(&pending_mints, mint_buffer, mint_bump).await.context("process remaining pending-mint groups")?;
    if !mint_result.fully_completed || mint_result.total_mints_processed != pending_mints.len() {
        bail!("mint processing incomplete: groups={}, mints={}, expected={}", mint_result.groups_processed, mint_result.total_mints_processed, pending_mints.len());
    }
    let recipient_balance = solana_rpc.get_token_account_balance(&args.recipient_token_account).await.context("read recipient balance")?;

    let proof_bytes = std::fs::read(&args.proof_path)?;
    let evidence = Evidence {
        schema: "doge-local-deposit-evidence-v1",
        completed: true,
        proof_system: "SP1 v6 Groth16",
        mock_zkp_requested: false,
        limitations: Limitations {
            environment: "local Dogecoin regtest and local Solana validator only",
            transition_semantics: "vout is used as the TXO index; next tip hash/root are synthetic [1;32] and time advances by 60 seconds",
            guest_semantics: "the block-transition guest proves a caller-supplied header/config/custodian hash relation, not Dogecoin consensus, canonical chain selection, transaction inclusion, or a bridge UTXO database",
            recipient_binding: "the operator supplies the recipient pDOGE token account; the current guest does not bind it to the Dogecoin deposit script",
            proof_warning: "356-byte length and host public-value validation are necessary but do not alone prove the binary or deployed program was built without mock-zkp",
            guardian_status: "noop shim configuration only; no Wormhole Guardian, VAA ingestion, TSS, or DOGE release service is exercised",
        },
        dogecoin: json!({
            "rpc_url": args.doge_rpc_url, "network": "regtest", "deposit_address": deposit_address,
            "txid": txid, "vout": deposit_vout, "amount_sats": deposit_sats,
            "confirmations": confirmations, "mined_blocks": args.mine_blocks,
            "custody_registered": store.is_some(),
        }),
        solana: json!({
            "rpc_url": args.solana_rpc_url, "operator": operator.pubkey().to_string(),
            "payer": payer.pubkey().to_string(), "recipient_token_account": args.recipient_token_account.to_string(),
            "recipient_balance": recipient_balance, "bridge_state": derived_bridge_state.to_string(),
            "programs": { "doge_bridge": args.doge_bridge_program.to_string(), "pending_mint": args.pending_mint_program.to_string(), "txo_buffer": args.txo_buffer_program.to_string(), "generic_buffer": args.generic_buffer_program.to_string(), "manual_claim": args.manual_claim_program.to_string(), "noop_shim": args.noop_shim_program.to_string() },
            "block_update_signature": block_update_signature.to_string(), "compute_unit_limit": 1_400_000,
        }),
        buffers: json!({
            "pending_mint": mint_buffer.to_string(), "pending_mint_bump": mint_bump,
            "pending_mints_hash": hex::encode(pending_mints_hash), "txo": txo_buffer.to_string(),
            "txo_bump": txo_bump, "txo_indices": txo_indices, "txo_hash": hex::encode(txo_hash),
        }),
        block_transition: json!({
            "old_header_hex": hex::encode(old_header_bytes), "new_header_hex": hex::encode(new_header_bytes),
            "config_params_hex": hex::encode(config_bytes), "custodian_hash_hex": hex::encode(pre_state.custodian_wallet_config_hash),
            "proof_path": args.proof_path, "proof_size": GROTH16_PROOF_SIZE,
            "proof_sha256": hex::encode(Sha256::digest(&proof_bytes)),
            "public_values_path": args.public_values_path, "public_values_size": BLOCK_PUBLIC_VALUES_SIZE,
            "public_values_hex": hex::encode(public_values), "prover_stdout": prover_output,
        }),
        mint_processing: json!({
            "groups_processed": mint_result.groups_processed, "mints_processed": mint_result.total_mints_processed,
            "fully_completed": mint_result.fully_completed,
            "signatures": mint_result.signatures.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
        operator_store: json!({
            "enabled": store.is_some(), "path": args.operator_store,
            "custody_txid": txid, "custody_vout": deposit_vout, "leaf_index": leaf_index.to_string(),
        }),
    };
    write_evidence(&args.evidence_path, &evidence)?;
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

fn read_keypair(path: &Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path).map_err(|error| anyhow!("read {role} keypair {}: {error}", path.display()))
}

fn clone_keypair(keypair: &Keypair) -> Result<Keypair> {
    Keypair::from_bytes(&keypair.to_bytes()).context("clone Solana keypair")
}

async fn assert_regtest(doge: &DogeRpc) -> Result<()> {
    let chain = doge.call("getblockchaininfo", json!([])).await?
        .get("chain").and_then(Value::as_str).map(str::to_owned)
        .ok_or_else(|| anyhow!("getblockchaininfo missing chain"))?;
    if chain != "regtest" { bail!("refusing Dogecoin chain {chain}"); }
    Ok(())
}

fn sats_to_doge_json(sats: u64) -> Result<Value> {
    let text = format!("{}.{:08}", sats / SATS_PER_DOGE, sats % SATS_PER_DOGE);
    serde_json::from_str(&text).with_context(|| format!("encode {sats} sats"))
}

async fn poll_deposit(doge: &DogeRpc, txid: &str, min_confirm: u64, timeout: Duration, interval: Duration) -> Result<Value> {
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    loop {
        match doge.call("getrawtransaction", json!([txid, true])).await {
            Ok(verbose) => {
                let c = verbose.get("confirmations").and_then(Value::as_u64).unwrap_or_default();
                if c >= min_confirm { return Ok(verbose); }
                last_error = Some(format!("only {c} confirmations"));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for deposit {txid}: {}", last_error.unwrap_or_default());
        }
        sleep(interval).await;
    }
}

fn compute_mints_hash(mints: &[PendingMint]) -> [u8; 32] {
    if mints.is_empty() { return PM_DA_DEFAULT_PENDING_MINTS_BUFFER_HASH; }
    let mut preimage = Vec::with_capacity(2 + mints.len().div_ceil(PM_MAX_PENDING_MINTS_PER_GROUP) * 32);
    preimage.extend_from_slice(&(mints.len() as u16).to_le_bytes());
    for group in mints.chunks(PM_MAX_PENDING_MINTS_PER_GROUP) {
        let mut bytes = Vec::with_capacity(std::mem::size_of_val(group));
        for mint in group { bytes.extend_from_slice(bytemuck::bytes_of(mint)); }
        preimage.extend_from_slice(&hash_impl_sha256_bytes(&bytes));
    }
    hash_impl_sha256_bytes(&preimage)
}

fn compute_txo_hash(indices: &[u32]) -> [u8; 32] {
    if indices.is_empty() { return PM_TXO_DEFAULT_BUFFER_HASH; }
    let mut bytes = Vec::with_capacity(indices.len() * 4);
    for index in indices { bytes.extend_from_slice(&index.to_le_bytes()); }
    hash_impl_sha256_bytes(&bytes)
}

fn remove_stale_artifact(path: &Path) -> Result<()> {
    if path.exists() { std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?; }
    Ok(())
}

async fn invoke_gen_proof(binary: &Path, old_header: &[u8], new_header: &[u8], config: &[u8], custodian_hash: &[u8; 32]) -> Result<String> {
    let output = Command::new(binary)
        .arg("--old-header").arg(hex::encode(old_header))
        .arg("--new-header").arg(hex::encode(new_header))
        .arg("--config-params").arg(hex::encode(config))
        .arg("--custodian-hash").arg(hex::encode(custodian_hash))
        .output().await.with_context(|| format!("execute SP1 gen-proof {}", binary.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() { bail!("SP1 gen-proof failed: {}\n{stdout}\n{stderr}", output.status); }
    if !stderr.trim().is_empty() { eprintln!("SP1 stderr:\n{stderr}"); }
    Ok(stdout)
}

fn write_evidence(path: &Path, evidence: &Evidence) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) { std::fs::create_dir_all(parent)?; }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(evidence)?).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sats_encode_without_float_rounding() {
        assert_eq!(sats_to_doge_json(1).unwrap(), serde_json::from_str::<Value>("0.00000001").unwrap());
        assert_eq!(doge_amount_to_sats(&sats_to_doge_json(12_345_678_901).unwrap()).unwrap(), 12_345_678_901);
    }
    #[test]
    fn one_mint_hash_matches_reference_layout() {
        let mint = PendingMint { recipient: [3u8; 32], amount: 42 };
        let mut group = Vec::new();
        group.extend_from_slice(bytemuck::bytes_of(&mint));
        let mut preimage = 1u16.to_le_bytes().to_vec();
        preimage.extend_from_slice(&hash_impl_sha256_bytes(&group));
        assert_eq!(compute_mints_hash(&[mint]), hash_impl_sha256_bytes(&preimage));
    }
}
