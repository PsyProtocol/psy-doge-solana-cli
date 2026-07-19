//! Authenticated one-time devnet Bridge State layout migration.

use anyhow::{bail, Context, Result};
use clap::Parser;
use doge_bridge_client::instructions::migrate_legacy_bridge_state;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    bpf_loader_upgradeable,
    message::Message,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    transaction::Transaction,
};

use crate::network::{fill_string, RuntimeNetwork};

const DOGE_BRIDGE_PROGRAM: &str = "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ";
const BRIDGE_STATE_SIZE_BEFORE: usize = 6_264;
const BRIDGE_STATE_SIZE_AFTER: usize = 6_224;

#[derive(Debug, Parser)]
#[command(
    name = "migrate-bridge-state",
    about = "Migrate the audited live 6,264-byte devnet Bridge State to 6,224 bytes"
)]
pub struct Args {
    #[arg(skip)]
    runtime_network: RuntimeNetwork,
    #[arg(long, help = "Solana RPC URL override")]
    solana_rpc_url: Option<String>,
    #[arg(long)]
    payer_keypair: std::path::PathBuf,
    #[arg(long)]
    operator_keypair: std::path::PathBuf,
    #[arg(long)]
    upgrade_authority_keypair: std::path::PathBuf,
    #[arg(long, default_value = DOGE_BRIDGE_PROGRAM)]
    doge_bridge_program: Pubkey,
}

impl Args {
    pub fn apply_network_defaults(&mut self, network: RuntimeNetwork) {
        self.runtime_network = network;
        fill_string(&mut self.solana_rpc_url, network.defaults().solana_rpc_url);
    }

    fn solana_rpc_url(&self) -> &str {
        self.solana_rpc_url
            .as_deref()
            .expect("solana_rpc_url requires apply_network_defaults")
    }
}

pub async fn run(args: Args) -> Result<()> {
    if args.runtime_network != RuntimeNetwork::Devnet {
        bail!("migrate-bridge-state is only allowed with --network devnet");
    }
    args.runtime_network
        .validate_remote_url("Solana RPC", args.solana_rpc_url())?;
    if args.doge_bridge_program.to_string() != DOGE_BRIDGE_PROGRAM {
        bail!("migrate-bridge-state is fixed to deployed DBjo program {DOGE_BRIDGE_PROGRAM}");
    }

    let payer = read_keypair(&args.payer_keypair, "payer")?;
    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let upgrade_authority = read_keypair(&args.upgrade_authority_keypair, "upgrade authority")?;
    let rpc = RpcClient::new(args.solana_rpc_url().to_owned());
    let (bridge_state, _) = Pubkey::find_program_address(&[b"bridge_state"], &args.doge_bridge_program);
    let before = rpc
        .get_account(&bridge_state)
        .await
        .context("read Bridge State before migration")?;
    if before.owner != args.doge_bridge_program || before.data.len() != BRIDGE_STATE_SIZE_BEFORE {
        bail!(
            "Bridge State must be program-owned and exactly {BRIDGE_STATE_SIZE_BEFORE} bytes before migration; owner={} size={}",
            before.owner,
            before.data.len()
        );
    }

    let (programdata, _) = Pubkey::find_program_address(
        &[args.doge_bridge_program.as_ref()],
        &bpf_loader_upgradeable::id(),
    );
    let instruction = migrate_legacy_bridge_state(
        args.doge_bridge_program,
        payer.pubkey(),
        operator.pubkey(),
        programdata,
        upgrade_authority.pubkey(),
    );
    let blockhash = rpc.get_latest_blockhash().await?;
    let message = Message::new(&[instruction], Some(&payer.pubkey()));
    let transaction = Transaction::new(&[&payer, &operator, &upgrade_authority], message, blockhash);
    let signature = rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .context("submit authenticated Bridge State migration")?;

    let after = rpc
        .get_account(&bridge_state)
        .await
        .context("read Bridge State after migration")?;
    if after.owner != args.doge_bridge_program || after.data.len() != BRIDGE_STATE_SIZE_AFTER {
        bail!(
            "migration transaction {signature} confirmed but Bridge State verification failed: owner={} size={}",
            after.owner,
            after.data.len()
        );
    }
    println!(
        "Bridge State migration confirmed: signature={signature} pda={bridge_state} size={BRIDGE_STATE_SIZE_AFTER}"
    );
    Ok(())
}

fn read_keypair(path: &std::path::Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|error| anyhow::anyhow!("read {role} keypair {}: {error}", path.display()))
}
