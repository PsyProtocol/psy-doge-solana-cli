use clap::{Parser, Subcommand};
use doge_local_ops::commands;
use doge_local_ops::network::RuntimeNetwork;

#[derive(Parser)]
#[command(
    name = "doge-solana-cli",
    version,
    about = "Dogecoin ↔ Solana bridge CLI"
)]
struct Cli {
    /// Runtime network profile. localhost = regtest/local services; devnet = Solana devnet + Dogecoin testnet (no local services).
    #[arg(
        long,
        value_enum,
        global = true,
        default_value_t = RuntimeNetwork::Localhost,
        value_name = "NETWORK"
    )]
    network: RuntimeNetwork,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a Dogecoin deposit to bridge custody
    Deposit(commands::deposit_to_solana::Args),
    /// Process a withdrawal request end-to-end
    Withdraw(commands::process_withdrawal::Args),
    /// Run the operator daemon (polls for unprocessed withdrawals)
    Daemon(commands::operator_daemon::Args),
    /// Initialize bridge from Dogecoin chain data
    InitBridge(commands::init_bridge::Args),
    /// Run the complete local smoke flow (localhost only)
    LocalE2e(commands::local_e2e::Args),
    /// LOCALHOST ONLY: deterministic local Manager/VAA HTTP service
    #[command(hide = true)]
    ManagerService(commands::local_manager_service::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    match &mut cli.command {
        Commands::Deposit(args) => args.apply_network_defaults(cli.network),
        Commands::Withdraw(args) => args.apply_network_defaults(cli.network),
        Commands::Daemon(args) => args.apply_network_defaults(cli.network),
        Commands::InitBridge(args) => args.apply_network_defaults(cli.network),
        Commands::LocalE2e(_) => {}
        Commands::ManagerService(_) => {
            if !cli.network.is_localhost() {
                anyhow::bail!(
                    "manager-service is only allowed with --network localhost (got --network {})",
                    cli.network.as_str()
                );
            }
        }
    }

    match cli.command {
        Commands::Deposit(args) => commands::deposit_to_solana::run(args).await,
        Commands::Withdraw(args) => commands::process_withdrawal::run(args).await,
        Commands::Daemon(args) => commands::operator_daemon::run(args).await,
        Commands::InitBridge(args) => commands::init_bridge::run(args).await,
        Commands::LocalE2e(args) => commands::local_e2e::run(cli.network, args).await,
        Commands::ManagerService(args) => commands::local_manager_service::run(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_network_parses_before_subcommand() {
        let cli = Cli::try_parse_from([
            "doge-solana-cli",
            "--network",
            "devnet",
            "deposit",
            "--help",
        ]);
        assert!(cli.is_err_and(|error| error.kind() == clap::error::ErrorKind::DisplayHelp));
    }

    #[test]
    fn no_argument_invocation_never_selects_local_e2e() {
        assert!(Cli::try_parse_from(["doge-solana-cli"]).is_err());
    }

    #[test]
    fn local_e2e_is_an_explicit_command() {
        let cli = Cli::try_parse_from([
            "doge-solana-cli",
            "--network",
            "localhost",
            "local-e2e",
        ])
        .unwrap();
        assert_eq!(cli.network, RuntimeNetwork::Localhost);
        assert!(matches!(cli.command, Commands::LocalE2e(_)));
    }
}
