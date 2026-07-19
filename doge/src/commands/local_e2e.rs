//! Localhost-only launcher for the complete local validation flow.
//!
//! Spawns the internal `bun tools/local/runner.ts --network localhost` from a
//! safely resolved CLI repo root. Never starts on `--network devnet`.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::network::RuntimeNetwork;

#[derive(Debug, Parser)]
#[command(
    name = "local-e2e",
    about = "Run the complete local validation flow (localhost only)",
    long_about = "Resolves the CLI repo root, then launches the internal Bun validation runner with isolated state and ports. Rejected on --network devnet before any process is spawned. Optional --projects-dir selects the source sibling repositories. Runner-owned services are always stopped before the command exits."
)]
pub struct Args {
    /// Source sibling-repository root used to build an isolated temporary project tree.
    #[arg(long)]
    projects_dir: Option<PathBuf>,
}

pub async fn run(network: RuntimeNetwork, args: Args) -> Result<()> {
    if !network.is_localhost() {
        bail!(
            "local-e2e is only allowed with --network localhost (got --network {})",
            network.as_str()
        );
    }

    let repo_root = resolve_cli_repo_root().context("resolve CLI repo root for local-e2e")?;
    let runner = repo_root.join("tools/local/runner.ts");
    if !runner.is_file() {
        bail!(
            "local validation runner missing at {}",
            runner.display()
        );
    }

    let bun = find_bun().context("locate bun executable for local-e2e")?;
    let mut command = tokio::process::Command::new(&bun);
    command
        .current_dir(&repo_root)
        .arg(runner.as_os_str())
        .arg("--network")
        .arg("localhost")
        .kill_on_drop(true)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(projects_dir) = args.projects_dir.as_ref() {
        let projects_dir = fs::canonicalize(projects_dir).with_context(|| {
            format!(
                "canonicalize --projects-dir {}",
                projects_dir.display()
            )
        })?;
        command.env("PSY_DOGE_PROJECTS_DIR", &projects_dir);
    }

    // Inherit the caller environment so optional binary overrides reach the
    // internal runner unchanged.
    eprintln!(
        "local-e2e: spawning internal runner {} with --network localhost (cwd={})",
        runner.display(),
        repo_root.display()
    );

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn bun smoke launcher from {}", repo_root.display()))?;
    let status = tokio::select! {
        status = child.wait() => status.context("wait for local-e2e runner")?,
        signal = wait_for_shutdown_signal() => {
            signal?;
            shutdown_child(&mut child).await?
        }
    };
    if status.success() {
        Ok(())
    } else {
        match status.code() {
            Some(code) => bail!("local-e2e smoke flow exited with status {code}"),
            None => bail!("local-e2e smoke flow terminated by signal"),
        }
    }
}

/// Gracefully terminate the spawned runner: forward SIGTERM on Unix and give
/// the process a bounded window to clean up its owned services, then escalate
/// to a force kill. The non-Unix fallback preserves the original portable
/// `start_kill()` behavior.
async fn shutdown_child(child: &mut tokio::process::Child) -> Result<std::process::ExitStatus> {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            // SAFETY: `kill` targets our own child PID with a standard signal;
            // per POSIX this is well-defined and does not touch the caller's
            // signal disposition.
            let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            if rc != 0 {
                // Process may have already exited; fall through to the wait so
                // we observe the status rather than treating it as a hard
                // failure.
                let _ = child.start_kill();
            }
        }
        match tokio::time::timeout(
            Duration::from_secs(SHUTDOWN_GRACE_SECS),
            child.wait(),
        )
        .await
        {
            Ok(result) => result.context("wait for terminated local-e2e runner"),
            Err(_) => {
                eprintln!(
                    "local-e2e: runner did not exit within {SHUTDOWN_GRACE_SECS}s after SIGTERM; force killing"
                );
                let _ = child.start_kill();
                child
                    .wait()
                    .await
                    .context("wait for force-killed local-e2e runner")
            }
        }
    }
    #[cfg(not(unix))]
    {
        child
            .start_kill()
            .context("terminate local-e2e runner")?;
        child
            .wait()
            .await
            .context("wait for terminated local-e2e runner")
    }
}

/// Bounded grace window (seconds) the runner gets to tear down its owned
/// services after SIGTERM before we escalate to SIGKILL.
const SHUTDOWN_GRACE_SECS: u64 = 8;

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn find_bun() -> Result<PathBuf> {
    if let Ok(explicit) = env::var("BUN_BIN") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Ok(path);
        }
        bail!("BUN_BIN does not point at a file: {}", path.display());
    }
    if let Some(path) = env_path_lookup("bun") {
        return Ok(path);
    }
    bail!("bun not found on PATH (set BUN_BIN to override)");
}

fn env_path_lookup(command: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Walk from the running executable (and cwd fallback) until the CLI repo root
/// that contains `tools/local/runner.ts` is found.
fn resolve_cli_repo_root() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(override_root) = env::var("DOGE_SOLANA_CLI_ROOT") {
        candidates.push(PathBuf::from(override_root));
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.to_path_buf());
            if let Ok(canon) = fs::canonicalize(parent) {
                candidates.push(canon);
            }
        }
    }
    if let Ok(cwd) = env::current_dir() {
        candidates.push(cwd.clone());
        if let Ok(canon) = fs::canonicalize(&cwd) {
            candidates.push(canon);
        }
    }

    let mut seen = Vec::new();
    for start in candidates {
        let mut cursor = start;
        for _ in 0..12 {
            if seen.iter().any(|p: &PathBuf| p == &cursor) {
                break;
            }
            seen.push(cursor.clone());
            if is_cli_repo_root(&cursor) {
                return Ok(fs::canonicalize(&cursor).unwrap_or(cursor));
            }
            match cursor.parent() {
                Some(parent) if parent != cursor => cursor = parent.to_path_buf(),
                _ => break,
            }
        }
    }

    bail!(
        "could not locate CLI repo root containing tools/local/runner.ts \
         (run from the repo, install the binary under doge/target/..., or set DOGE_SOLANA_CLI_ROOT)"
    );
}

fn is_cli_repo_root(path: &Path) -> bool {
    path.join("tools/local/runner.ts").is_file()
        && (path.join("doge/Cargo.toml").is_file() || path.join("package.json").is_file())
}
