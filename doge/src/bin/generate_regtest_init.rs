use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use bytemuck::bytes_of;
use clap::Parser;
use doge_light_client::{
    hash::sha256_impl::hash_impl_sha256_bytes, network_params::DogeNetworkType,
};
use psy_bridge_core::header::{
    PsyBridgeHeader, PsyBridgeStateCommitment, PsyBridgeTipStateCommitment,
};
use psy_doge_bridge_helper::tx_template::CustodyScriptConfig;
use psy_doge_data_link::link_sync::{
    block_header_cache::BlockHeaderFetcher, bridge_state_helpers::gen_bridge_initial_state,
    electrs_link::DogeLinkElectrsClient,
};
use psy_doge_solana_core::{
    data_accounts::pending_mint::{
        PM_DA_DEFAULT_PENDING_MINTS_BUFFER_HASH, PM_TXO_DEFAULT_BUFFER_HASH,
    },
    instructions::doge_bridge::InitializeBridgeInstructionDataDoge,
};
use serde::{Deserialize, Serialize};

const HEADER_CACHE_SIZE: usize = 32;
const BLOCK_TREE_HEIGHT: usize = 28;
const EXPECTED_CUSTODIAN_HASH_HEX: &str =
    "afae9579f67ecff79ea3297a58a4c814a4582020abd4e6d3f5e3b19b46f1ab69";

#[derive(Debug, Parser)]
#[command(
    about = "Generate a per-run regtest InitializeBridgeInstructionDataDoge config from Electrs"
)]
struct Args {
    /// Checked-in InitializeBridgeInstructionDataDoge JSON whose fee/return settings are preserved.
    #[arg(long)]
    template: PathBuf,

    /// Destination for the generated per-run JSON. The template is never modified.
    #[arg(long)]
    output: PathBuf,

    /// Electrs HTTP endpoint serving the same Dogecoin regtest chain as the local daemon.
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    electrs_url: String,

    /// Finalized checkpoint height. Must be indexed by Electrs and have at least 32 headers.
    #[arg(long)]
    checkpoint_height: u32,
    /// Confirmation depth used by the block pipeline and old-header commitment.
    #[arg(long, default_value_t = 1)]
    required_confirmations: u32,

    /// Dogecoin Core getblockhash(checkpoint_height), in RPC/display byte order.
    #[arg(long)]
    expected_block_hash: String,

    /// Exact 32-byte custody-script config preimage (the bridge-state PDA bytes).
    #[arg(long)]
    custody_script_config: String,
}

#[derive(Debug, Serialize)]
struct GeneratorOutput {
    schema: &'static str,
    config_path: String,
    checkpoint_height: u32,
    checkpoint_hash: String,
    next_height: u32,
    first_cached_height: u32,
    cached_header_count: usize,
    bridge_header_bytes: usize,
    bridge_header_hex: String,
    bridge_state_hash: String,
    custody_script_config: String,
    custodian_wallet_config_hash: String,
}

#[derive(Debug, Deserialize)]
struct ElectrsBlockStatus {
    in_best_chain: bool,
    height: Option<u32>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.checkpoint_height + 1 < HEADER_CACHE_SIZE as u32 {
        bail!(
            "checkpoint height {} is too low for the {}-header cache",
            args.checkpoint_height,
            HEADER_CACHE_SIZE
        );
    }

    let expected_block_hash = normalize_hash(&args.expected_block_hash, "expected block hash")?;
    let custody_script_config =
        decode_fixed::<32>(&args.custody_script_config, "custody script config")?;
    let custodian_wallet_config_hash = CustodyScriptConfig::new(custody_script_config).hash();
    let custodian_hash_hex = hex::encode(custodian_wallet_config_hash);
    if custodian_hash_hex != EXPECTED_CUSTODIAN_HASH_HEX {
        bail!(
            "full manager custody config hashes to {}, expected canonical local bridge hash {}",
            custodian_hash_hex,
            EXPECTED_CUSTODIAN_HASH_HEX
        );
    }

    let template_text = fs::read_to_string(&args.template)
        .with_context(|| format!("read template {}", args.template.display()))?;
    let template: InitializeBridgeInstructionDataDoge = serde_json::from_str(&template_text)
        .with_context(|| {
            format!(
                "parse {} as InitializeBridgeInstructionDataDoge JSON",
                args.template.display()
            )
        })?;

    let client = DogeLinkElectrsClient::new(args.electrs_url.clone(), DogeNetworkType::RegTest);
    let electrs_tip = client
        .get_block_height()
        .with_context(|| format!("read Electrs tip from {}", args.electrs_url))?;
    if args.checkpoint_height > electrs_tip {
        bail!(
            "checkpoint height {} exceeds Electrs tip {}",
            args.checkpoint_height,
            electrs_tip
        );
    }
    let electrs_hash = normalize_hash(
        &client
            .get_text(&format!("block-height/{}", args.checkpoint_height))
            .context("read checkpoint hash from Electrs")?,
        "Electrs checkpoint hash",
    )?;
    if electrs_hash != expected_block_hash {
        bail!(
            "chain identity mismatch at height {}: Dogecoin RPC {} != Electrs {}",
            args.checkpoint_height,
            expected_block_hash,
            electrs_hash
        );
    }
    let status: ElectrsBlockStatus = client
        .get_json(&format!("block/{electrs_hash}/status"))
        .context("read Electrs checkpoint status")?;
    if !status.in_best_chain || status.height != Some(args.checkpoint_height) {
        bail!(
            "Electrs checkpoint {} is not the best-chain block at height {}: {:?}",
            electrs_hash,
            args.checkpoint_height,
            status
        );
    }

    let mut fetcher = BlockHeaderFetcher::new(client);
    let state = gen_bridge_initial_state::<_, HEADER_CACHE_SIZE, BLOCK_TREE_HEIGHT>(
        &mut fetcher,
        args.checkpoint_height,
    )
    .context("generate 32-header regtest chain state")?;
    let mut tip_rpc_hash = state.get_tip_block_hash();
    tip_rpc_hash.reverse();
    let tip_rpc_hash = hex::encode(tip_rpc_hash);
    if tip_rpc_hash != expected_block_hash {
        bail!(
            "generated light-client tip {} does not match Dogecoin checkpoint {}",
            tip_rpc_hash,
            expected_block_hash
        );
    }

    let tip = state.block_data_tracker.get_tip_state_commitment();
    let finalized = state
        .block_data_tracker
        .get_finalized_state_commitment(args.required_confirmations)
        .context("read generated finalized commitment")?;
    let finalized_record = state
        .block_data_tracker
        .get_record(finalized.block_height)
        .context("read finalized block record")?;
    let bridge_state_hash = hash_impl_sha256_bytes(&borsh::to_vec(&state)?);
    let bridge_header = PsyBridgeHeader {
        tip_state: PsyBridgeTipStateCommitment {
            block_hash: tip.block_hash,
            block_merkle_tree_root: tip.block_merkle_tree_root,
            block_time: finalized_record.timestamp.into(),
            block_height: tip.block_height,
        },
        finalized_state: PsyBridgeStateCommitment {
            block_hash: finalized.block_hash,
            block_merkle_tree_root: finalized.block_merkle_tree_root,
            pending_mints_finalized_hash: PM_DA_DEFAULT_PENDING_MINTS_BUFFER_HASH,
            txo_output_list_finalized_hash: PM_TXO_DEFAULT_BUFFER_HASH,
            auto_claimed_txo_tree_root: finalized.auto_claimed_txo_tree_root,
            auto_claimed_deposits_tree_root: finalized.auto_claimed_deposits_tree_root,
            auto_claimed_deposits_next_index: finalized.auto_claimed_deposits_next_index,
            block_height: finalized.block_height,
        },
        bridge_state_hash,
        last_rollback_at_secs: 0,
        paused_until_secs: 0,
        total_finalized_fees_collected_chain_history: finalized_record
            .total_fees_collected_chain_history
            .into(),
    };
    let bridge_header_bytes = bytes_of(&bridge_header);
    if bridge_header_bytes.len() != 320 {
        bail!(
            "generated Solana bridge header is {} bytes, expected 320",
            bridge_header_bytes.len()
        );
    }

    let generated = InitializeBridgeInstructionDataDoge {
        bridge_header,
        start_return_txo_output: template.start_return_txo_output,
        config_params: template.config_params,
        custodian_wallet_config_hash,
    };
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    fs::write(&args.output, serde_json::to_vec_pretty(&generated)?)
        .with_context(|| format!("write generated config {}", args.output.display()))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&GeneratorOutput {
            schema: "InitializeBridgeInstructionDataDoge",
            config_path: args.output.display().to_string(),
            checkpoint_height: args.checkpoint_height,
            checkpoint_hash: expected_block_hash,
            next_height: args.checkpoint_height + 1,
            first_cached_height: args.checkpoint_height + 1 - HEADER_CACHE_SIZE as u32,
            cached_header_count: HEADER_CACHE_SIZE,
            bridge_header_bytes: bridge_header_bytes.len(),
            bridge_header_hex: hex::encode(bridge_header_bytes),
            bridge_state_hash: hex::encode(bridge_state_hash),
            custody_script_config: hex::encode(custody_script_config),
            custodian_wallet_config_hash: custodian_hash_hex,
        })?
    );
    Ok(())
}

fn normalize_hash(value: &str, name: &str) -> Result<String> {
    let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let bytes = hex::decode(normalized).with_context(|| format!("decode {name} as hex"))?;
    if bytes.len() != 32 {
        bail!("{name} must be 32 bytes, got {}", bytes.len());
    }
    Ok(hex::encode(bytes))
}

fn decode_fixed<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let bytes = hex::decode(normalized).with_context(|| format!("decode {name} as hex"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{name} must be {N} bytes, got {}", bytes.len()))
}
