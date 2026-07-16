//! Long-running operator daemon.
//!
//! Continuously polls the Doge bridge state on Solana for unprocessed withdrawal
//! requests. When the live requested-withdrawals tree has advanced past the last
//! snapshot, the daemon refreshes the on-chain snapshot (`execute_snapshot_withdrawals`)
//! so pending requests become visible. It then detects any request whose index sits
//! between `next_processed_withdrawals_index` and
//! `withdrawal_snapshot.next_requested_withdrawals_tree_index` and drives the atomic
//! authorize/VAA → manager relay/broadcast → confirm → finalize flow by spawning
//! the one-shot `process_withdrawal` binary as a subprocess.
//!
//! Errors during a poll cycle are logged and the loop continues; the daemon never
//! crashes on a transient failure. A failed subprocess leaves
//! `next_processed_withdrawals_index` unchanged, so the same request is retried on
//! the next cycle.

use anyhow::{Context, Result};
use clap::Parser;
use doge_bridge_client::{
    constants::BRIDGE_STATE_SEED, BridgeApi, BridgeClient, BridgeClientConfigBuilder, OperatorApi,
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair},
};
use std::{path::PathBuf, str::FromStr, time::Duration};
use tokio::{process::Command, time::sleep};

const DEFAULT_DOGE_BRIDGE: &str = "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ";
// Wormhole program IDs are required to build a BridgeClient but are not exposed on
// the daemon CLI: they mirror the defaults used by `process_withdrawal` so the two
// binaries always agree on the Wormhole programs in the local-regtest fixture.
const DEFAULT_WORMHOLE_CORE_PROGRAM: &str = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";
const DEFAULT_WORMHOLE_SHIM_PROGRAM: &str = "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";

#[derive(Debug, Parser)]
#[command(
    name = "operator-daemon",
    about = "Long-running operator that polls Solana for unprocessed withdrawal requests and drives the atomic output-only flow via the process_withdrawal binary",
    long_about = "Polls the Doge bridge state, refreshes the withdrawal snapshot when the requested-withdrawals tree advances, and spawns the one-shot `process_withdrawal` subprocess for each unprocessed request. Errors are logged and the loop continues."
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    solana_rpc_url: String,
    #[arg(long)]
    operator_keypair: PathBuf,
    #[arg(long)]
    payer_keypair: PathBuf,
    #[arg(long)]
    operator_store: PathBuf,
    #[arg(long, default_value = DEFAULT_DOGE_BRIDGE)]
    doge_bridge_program: Pubkey,
    #[arg(long, default_value = "target/release/process_withdrawal")]
    process_withdrawal_bin: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:7071")]
    manager_service_url: String,
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    electrs_url: String,
    #[arg(long, default_value = "http://127.0.0.1:22555")]
    doge_rpc_url: String,
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,
    #[arg(long, default_value_t = 0)]
    manager_set_index: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.poll_interval_secs == 0 {
        anyhow::bail!("--poll-interval-secs must be greater than 0");
    }

    let bridge_state_pda =
        Pubkey::find_program_address(&[BRIDGE_STATE_SEED], &args.doge_bridge_program).0;
    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;

    let wormhole_core_program =
        Pubkey::from_str(DEFAULT_WORMHOLE_CORE_PROGRAM).expect("default wormhole core pubkey");
    let wormhole_shim_program =
        Pubkey::from_str(DEFAULT_WORMHOLE_SHIM_PROGRAM).expect("default wormhole shim pubkey");

    let client_config = BridgeClientConfigBuilder::new()
        .rpc_url(args.solana_rpc_url.clone())
        .bridge_state_pda(bridge_state_pda)
        .operator(operator)
        .payer(payer)
        .program_id(args.doge_bridge_program)
        .wormhole_core_program_id(wormhole_core_program)
        .wormhole_shim_program_id(wormhole_shim_program)
        .build()
        .context("build bridge client config")?;
    let bridge_client =
        BridgeClient::with_config(client_config).context("initialize bridge client")?;

    eprintln!(
        "operator-daemon started: bridge_state={bridge_state_pda} operator={} poll_interval={}s",
        bridge_client.operator_pubkey(),
        args.poll_interval_secs,
    );

    let poll_interval = Duration::from_secs(args.poll_interval_secs);
    loop {
        if let Err(error) = poll_once(&args, &bridge_client).await {
            eprintln!("poll cycle error: {error:#}");
        }
        sleep(poll_interval).await;
    }
}

/// One poll cycle: refresh the snapshot if stale, then drive one unprocessed request.
async fn poll_once(args: &Args, bridge_client: &BridgeClient) -> Result<()> {
    let state = bridge_client
        .get_current_bridge_state()
        .await
        .context("read current bridge state")?;

    // Refresh the on-chain snapshot when the live requested-withdrawals tree has
    // advanced past what the snapshot currently captures. Without this, newly
    // requested withdrawals stay invisible to the comparison below until some other
    // caller snapshots. The snapshot instruction is idempotent when the tree is
    // unchanged, so refreshing when stale is safe.
    let live_tree_next = state.requested_withdrawals_tree.next_index;
    let snapshot_next = state
        .withdrawal_snapshot
        .next_requested_withdrawals_tree_index;
    if live_tree_next > snapshot_next {
        eprintln!(
            "snapshot stale (requested_withdrawals_tree={live_tree_next} > snapshot={snapshot_next}); \
             executing snapshot_withdrawals"
        );
        bridge_client
            .execute_snapshot_withdrawals()
            .await
            .context("execute snapshot_withdrawals")?;
    }

    let state = bridge_client
        .get_current_bridge_state()
        .await
        .context("read bridge state after snapshot refresh")?;
    let next_processed = state.next_processed_withdrawals_index;
    let snapshot_next = state
        .withdrawal_snapshot
        .next_requested_withdrawals_tree_index;

    if next_processed >= snapshot_next {
        eprintln!(
            "no unprocessed withdrawals (next_processed={next_processed}, snapshot={snapshot_next})"
        );
        return Ok(());
    }

    let request_index = next_processed;
    eprintln!(
        "processing withdrawal request {request_index} (snapshot covers up to {snapshot_next})"
    );

    // Spawn the one-shot binary as the source of truth. It performs its own
    // snapshot, atomic authorization/VAA, manager relay, Dogecoin broadcast,
    // confirmation, and permissionless finalization. A non-zero exit leaves
    // `next_processed_withdrawals_index` unchanged, so the next cycle retries.
    let status = Command::new(&args.process_withdrawal_bin)
        .args(process_withdrawal_args(args, request_index))
        .status()
        .await
        .with_context(|| {
            format!(
                "spawn process_withdrawal binary at {}",
                args.process_withdrawal_bin.display()
            )
        })?;

    if !status.success() {
        eprintln!(
            "process_withdrawal for request {request_index} exited with {status}; \
             will retry next cycle"
        );
    } else {
        eprintln!("process_withdrawal for request {request_index} completed successfully");
    }

    Ok(())
}

fn process_withdrawal_args(args: &Args, request_index: u64) -> Vec<std::ffi::OsString> {
    [
        "--request-index".into(),
        request_index.to_string().into(),
        "--operator-keypair".into(),
        args.operator_keypair.as_os_str().to_owned(),
        "--payer-keypair".into(),
        args.payer_keypair.as_os_str().to_owned(),
        "--operator-store".into(),
        args.operator_store.as_os_str().to_owned(),
        "--solana-rpc-url".into(),
        args.solana_rpc_url.clone().into(),
        "--doge-bridge-program".into(),
        args.doge_bridge_program.to_string().into(),
        "--manager-service-url".into(),
        args.manager_service_url.clone().into(),
        "--electrs-url".into(),
        args.electrs_url.clone().into(),
        "--doge-rpc-url".into(),
        args.doge_rpc_url.clone().into(),
        "--manager-set-index".into(),
        args.manager_set_index.to_string().into(),
        "--manager-signing-enabled".into(),
        "--broadcast-enabled".into(),
    ]
    .into()
}

fn read_keypair(path: &std::path::Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|error| anyhow::anyhow!("read {role} keypair at {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawned_withdrawal_runs_live_sign_broadcast_flow() {
        let args = Args {
            solana_rpc_url: "http://solana".into(),
            operator_keypair: "operator.json".into(),
            payer_keypair: "payer.json".into(),
            operator_store: "operator.sqlite".into(),
            doge_bridge_program: Pubkey::new_unique(),
            process_withdrawal_bin: "process_withdrawal".into(),
            manager_service_url: "http://manager".into(),
            electrs_url: "http://electrs".into(),
            doge_rpc_url: "http://doge".into(),
            poll_interval_secs: 5,
            manager_set_index: 0,
        };
        let actual = process_withdrawal_args(&args, 9)
            .into_iter()
            .map(|arg| arg.into_string().expect("UTF-8 test arg"))
            .collect::<Vec<_>>();

        assert!(actual.iter().any(|arg| arg == "--manager-signing-enabled"));
        assert!(actual.iter().any(|arg| arg == "--broadcast-enabled"));
        assert_eq!(
            actual.windows(2).find(|pair| pair[0] == "--request-index"),
            Some(&["--request-index".to_owned(), "9".to_owned()][..])
        );
    }
}
