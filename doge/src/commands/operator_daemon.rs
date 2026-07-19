//! Long-running withdrawal operator.
//!
//! The daemon resumes any persisted incomplete batch before comparing the
//! requested-withdrawal tree tip with the snapshot cursor. New work is drained
//! in CPI-safe batches of at most 319 requests.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use doge_bridge_client::{
    constants::BRIDGE_STATE_SEED, operator_store::OperatorStore, BridgeApi, BridgeClient,
    BridgeClientConfigBuilder,
};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair},
};
use tokio::time::sleep;

use crate::network::{fill_string, fill_string_optional, fill_u32, RuntimeNetwork};

const DEFAULT_DOGE_BRIDGE: &str = "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ";

#[derive(Debug, Parser)]
#[command(
    name = "daemon",
    about = "Poll for unsnapshotted withdrawals and relay each snapshot batch to Dogecoin",
    long_about = "Long-running operator. Runtime endpoints, Manager set, and Wormhole programs are selected by the global --network flag."
)]
pub struct Args {
    /// Captured global runtime network for downstream withdraw dispatch.
    #[arg(skip)]
    runtime_network: RuntimeNetwork,
    #[arg(long, help = "Solana RPC URL override")]
    solana_rpc_url: Option<String>,
    #[arg(long)]
    operator_keypair: PathBuf,
    #[arg(long)]
    payer_keypair: PathBuf,
    #[arg(long)]
    operator_store: PathBuf,
    #[arg(long, default_value = DEFAULT_DOGE_BRIDGE)]
    doge_bridge_program: Pubkey,
    #[arg(long, help = "Manager HTTP service URL override")]
    manager_service_url: Option<String>,
    #[arg(long, help = "Electrs HTTP URL override")]
    electrs_url: Option<String>,
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,
    #[arg(
        long,
        help = "Manager set index override (default: 0 on localhost, 1 on devnet)"
    )]
    manager_set_index: Option<u32>,
    #[arg(long, help = "Wormhole Core program override")]
    wormhole_core_program: Option<Pubkey>,
    #[arg(long, help = "Wormhole Shim program override")]
    wormhole_shim_program: Option<Pubkey>,
}

impl Args {
    pub fn apply_network_defaults(&mut self, network: RuntimeNetwork) {
        self.runtime_network = network;
        let defaults = network.defaults();
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
            anyhow::anyhow!(
                "--manager-service-url is required on --network devnet \
                 (localhost defaults to the local Manager service)"
            )
        })
    }

    fn wormhole_core_program(&self) -> Pubkey {
        self.wormhole_core_program
            .expect("wormhole_core_program requires apply_network_defaults")
    }

    fn wormhole_shim_program(&self) -> Pubkey {
        self.wormhole_shim_program
            .expect("wormhole_shim_program requires apply_network_defaults")
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
}

pub async fn run(args: Args) -> Result<()> {
    args.validate_network_boundary()?;
    if args.poll_interval_secs == 0 {
        anyhow::bail!("--poll-interval-secs must be greater than 0");
    }
    let mut store = OperatorStore::open(&args.operator_store).context("open operator store")?;
    let _guard = store
        .acquire_operator_lock("operator-daemon")
        .context("acquire daemon operator lock")?;
    let bridge_state =
        Pubkey::find_program_address(&[BRIDGE_STATE_SEED], &args.doge_bridge_program).0;
    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;
    let client = BridgeClient::with_config(
        BridgeClientConfigBuilder::new()
            .rpc_url(args.solana_rpc_url().to_owned())
            .bridge_state_pda(bridge_state)
            .operator(operator)
            .payer(payer)
            .program_id(args.doge_bridge_program)
            .wormhole_core_program_id(args.wormhole_core_program())
            .wormhole_shim_program_id(args.wormhole_shim_program())
            .build()
            .context("build bridge client config")?,
    )
    .context("initialize bridge client")?;

    eprintln!(
        "operator-daemon started: bridge_state={bridge_state} poll_interval={}s network={}",
        args.poll_interval_secs,
        args.runtime_network.as_str()
    );
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        let mut failures = PollFailureTracker::new(POLL_FAILURE_THRESHOLD);
        loop {
            let cycle = tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = terminate.recv() => break,
                result = poll_once(&args, &client, &mut store) => result,
            };
            match cycle {
                Ok(()) => failures.record_success(),
                Err(error) => {
                    let reached = failures.record_failure();
                    eprintln!(
                        "poll cycle error (consecutive={}): {error:#}",
                        failures.consecutive()
                    );
                    if reached {
                        return Err(anyhow::anyhow!(
                            "operator-daemon aborting after {POLL_FAILURE_THRESHOLD} consecutive poll failures"
                        )
                        .context(error));
                    }
                }
            }
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = terminate.recv() => break,
                _ = sleep(Duration::from_secs(args.poll_interval_secs)) => {}
            }
        }
    }
    #[cfg(not(unix))]
    {
        let mut failures = PollFailureTracker::new(POLL_FAILURE_THRESHOLD);
        loop {
            let cycle = tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                result = poll_once(&args, &client, &mut store) => result,
            };
            match cycle {
                Ok(()) => failures.record_success(),
                Err(error) => {
                    let reached = failures.record_failure();
                    eprintln!(
                        "poll cycle error (consecutive={}): {error:#}",
                        failures.consecutive()
                    );
                    if reached {
                        return Err(anyhow::anyhow!(
                            "operator-daemon aborting after {POLL_FAILURE_THRESHOLD} consecutive poll failures"
                        )
                        .context(error));
                    }
                }
            }
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = sleep(Duration::from_secs(args.poll_interval_secs)) => {}
            }
        }
    }
    eprintln!("operator-daemon stopped");
    Ok(())
}

/// Bounded consecutive-poll-failure tracker. The daemon polls in a loop and
/// historically swallowed every `poll_once` error forever, which masks
/// permanent outages (dead RPC, revoked credentials, persistent store
/// corruption) behind an infinite stream of identical log lines. This counter
/// escalates a bounded run of consecutive failures to the supervisor as a
/// returned error. The count resets on any success, so transient flakiness is
/// still tolerated. Classification is purely count-based: errors are never
/// matched by message text.
#[derive(Debug, Clone)]
struct PollFailureTracker {
    consecutive: u32,
    threshold: u32,
}

impl PollFailureTracker {
    const fn new(threshold: u32) -> Self {
        Self {
            consecutive: 0,
            threshold,
        }
    }

    fn record_success(&mut self) {
        self.consecutive = 0;
    }

    /// Record one poll failure. Returns `true` once the consecutive-failure
    /// threshold has been reached (the caller should surface an error and
    /// stop). Uses saturating addition so a long outage cannot overflow.
    fn record_failure(&mut self) -> bool {
        self.consecutive = self.consecutive.saturating_add(1);
        self.consecutive >= self.threshold
    }

    fn consecutive(&self) -> u32 {
        self.consecutive
    }
}

/// Consecutive poll failures after which the daemon stops masking the outage
/// and returns an error to its supervisor.
const POLL_FAILURE_THRESHOLD: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollAction {
    Resume,
    Start(u64),
    Idle,
}

fn select_poll_action(
    has_incomplete_batch: bool,
    snapshot_cursor: u64,
    requested_cursor: u64,
) -> PollAction {
    if has_incomplete_batch {
        PollAction::Resume
    } else if snapshot_cursor < requested_cursor {
        PollAction::Start(snapshot_cursor)
    } else {
        PollAction::Idle
    }
}

async fn poll_once(
    args: &Args,
    bridge_client: &BridgeClient,
    store: &mut OperatorStore,
) -> Result<()> {
    if store.oldest_incomplete_snapshot_batch()?.is_some() {
        return dispatch_withdrawal(args, store, None, true).await;
    }
    let state = bridge_client
        .get_current_bridge_state()
        .await
        .context("read current bridge state")?;
    let snapshot_cursor = state
        .withdrawal_snapshot
        .next_requested_withdrawals_tree_index;
    let requested_cursor = state.requested_withdrawals_tree.next_index;
    let (request_index, resume) = match select_poll_action(false, snapshot_cursor, requested_cursor) {
        PollAction::Resume => (None, true),
        PollAction::Start(index) => (Some(index), false),
        PollAction::Idle => {
            eprintln!(
                "no withdrawal work (snapshot={snapshot_cursor}, requested={requested_cursor})"
            );
            return Ok(());
        }
    };

    dispatch_withdrawal(args, store, request_index, resume).await
}

async fn dispatch_withdrawal(
    args: &Args,
    store: &mut OperatorStore,
    request_index: Option<u64>,
    resume: bool,
) -> Result<()> {
    let mut withdraw_args = super::process_withdrawal::Args::try_parse_from(
        std::iter::once("withdraw".to_owned()).chain(
            process_withdrawal_args(args, request_index, resume)?
                .into_iter()
                .map(|value| value.to_string_lossy().into_owned()),
        ),
    )
    .context("parse process_withdrawal args")?;
    // Explicit endpoint flags come from this daemon; still apply the runtime
    // profile so internal Dogecoin network (and any unset fields) match.
    withdraw_args.apply_network_defaults(args.runtime_network);
    super::process_withdrawal::run_with_store(withdraw_args, store)
        .await
        .context("process or resume withdrawal snapshot batch")
}

fn process_withdrawal_args(
    args: &Args,
    request_index: Option<u64>,
    resume: bool,
) -> Result<Vec<std::ffi::OsString>> {
    let mut values = vec![
        "--operator-keypair".into(),
        args.operator_keypair.as_os_str().to_owned(),
        "--payer-keypair".into(),
        args.payer_keypair.as_os_str().to_owned(),
        "--operator-store".into(),
        args.operator_store.as_os_str().to_owned(),
        "--solana-rpc-url".into(),
        args.solana_rpc_url().into(),
        "--doge-bridge-program".into(),
        args.doge_bridge_program.to_string().into(),
        "--manager-service-url".into(),
        args.manager_service_url()?.into(),
        "--electrs-url".into(),
        args.electrs_url().into(),
        "--manager-set-index".into(),
        args.manager_set_index().to_string().into(),
        "--wormhole-core-program".into(),
        args.wormhole_core_program().to_string().into(),
        "--wormhole-shim-program".into(),
        args.wormhole_shim_program().to_string().into(),
        "--manager-signing-enabled".into(),
        "--broadcast-enabled".into(),
    ];
    if let Some(index) = request_index {
        values.push("--request-index".into());
        values.push(index.to_string().into());
    }
    if resume {
        values.push("--resume".into());
    }
    Ok(values)
}

fn read_keypair(path: &std::path::Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|error| anyhow::anyhow!("read {role} keypair {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            runtime_network: RuntimeNetwork::Localhost,
            solana_rpc_url: Some("http://solana".into()),
            operator_keypair: "operator.json".into(),
            payer_keypair: "payer.json".into(),
            operator_store: "operator.sqlite".into(),
            doge_bridge_program: Pubkey::new_unique(),
            manager_service_url: Some("http://manager".into()),
            electrs_url: Some("http://electrs".into()),
            poll_interval_secs: 5,
            manager_set_index: Some(0),
            wormhole_core_program: Some(Pubkey::new_unique()),
            wormhole_shim_program: Some(Pubkey::new_unique()),
        }
    }

    #[test]
    fn spawned_withdrawal_runs_snapshot_sign_broadcast_flow() {
        let actual = process_withdrawal_args(&args(), Some(9), false)
            .expect("build args")
            .into_iter()
            .map(|arg| arg.into_string().expect("UTF-8 test arg"))
            .collect::<Vec<_>>();
        assert!(actual.iter().any(|arg| arg == "--manager-signing-enabled"));
        assert!(actual.iter().any(|arg| arg == "--broadcast-enabled"));
        assert_eq!(
            actual.windows(2).find(|pair| pair[0] == "--request-index"),
            Some(&["--request-index".to_owned(), "9".to_owned()][..])
        );
        assert!(!actual.iter().any(|arg| arg == "--resume"));
    }

    #[test]
    fn p0_2_equal_cursors_with_incomplete_batch_resume() {
        assert_eq!(select_poll_action(true, 3, 3), PollAction::Resume);
        assert_eq!(select_poll_action(false, 3, 3), PollAction::Idle);
        assert_eq!(select_poll_action(false, 3, 4), PollAction::Start(3));
    }

    #[test]
    fn p0_2_resume_dispatch_does_not_target_live_cursor() {
        let actual = process_withdrawal_args(&args(), None, true)
            .expect("build args")
            .into_iter()
            .map(|arg| arg.into_string().expect("UTF-8 test arg"))
            .collect::<Vec<_>>();
        assert!(actual.iter().any(|arg| arg == "--resume"));
        assert!(!actual.iter().any(|arg| arg == "--request-index"));
        super::super::process_withdrawal::Args::try_parse_from(
            std::iter::once("withdraw".to_owned()).chain(actual),
        )
        .expect("resume arguments dispatch through process-withdrawal parser");
    }

    #[test]
    fn poll_failure_tracker_flags_threshold_not_before() {
        let mut tracker = PollFailureTracker::new(3);
        assert!(!tracker.record_failure(), "first failure must not trip");
        assert_eq!(tracker.consecutive(), 1);
        assert!(!tracker.record_failure(), "second failure must not trip");
        assert_eq!(tracker.consecutive(), 2);
        assert!(tracker.record_failure(), "third failure trips the threshold");
        assert_eq!(tracker.consecutive(), 3);
    }

    #[test]
    fn poll_failure_tracker_resets_on_success() {
        let mut tracker = PollFailureTracker::new(3);
        assert!(!tracker.record_failure());
        assert!(!tracker.record_failure());
        tracker.record_success();
        assert_eq!(tracker.consecutive(), 0);
        // After a reset, the same number of fresh failures is required again.
        assert!(!tracker.record_failure());
        assert!(!tracker.record_failure());
        assert!(tracker.record_failure());
    }

    #[test]
    fn poll_failure_tracker_threshold_one_aborts_immediately() {
        let mut tracker = PollFailureTracker::new(1);
        assert!(tracker.record_failure(), "threshold=1 must trip on first failure");
    }

    #[test]
    fn poll_failure_tracker_does_not_overflow_on_long_outage() {
        let mut tracker = PollFailureTracker::new(u32::MAX);
        // Place the counter at the wrap boundary; saturating add must cap at
        // `u32::MAX` instead of panicking on overflow.
        tracker.consecutive = u32::MAX - 1;
        assert!(tracker.record_failure());
        assert_eq!(tracker.consecutive(), u32::MAX);
        // A failure past the cap must saturate, not overflow.
        tracker.record_failure();
        assert_eq!(tracker.consecutive(), u32::MAX);
    }
}
