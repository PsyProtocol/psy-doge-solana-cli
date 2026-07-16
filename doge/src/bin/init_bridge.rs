//! One-shot CLI: create DOGE SPL mint (bridge PDA as authority) and initialize the bridge.

use anyhow::{bail, Context, Result};
use clap::Parser;
use doge_bridge_client::{
    BridgeApi, BridgeClient, BridgeClientConfigBuilder, OperatorApi, PsyBridgeConfig,
    PsyBridgeHeader, PsyReturnTxOutput,
};
use psy_doge_solana_core::instructions::doge_bridge::InitializeBridgeParams;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use std::path::PathBuf;
use std::str::FromStr;

const DEFAULT_DOGE_BRIDGE: &str = "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ";
const DEFAULT_PENDING_MINT: &str = "PMUSqycT1j5JTLmHk8frGSCido2h9VG1pyh2MPEa33o";
const DEFAULT_TXO_BUFFER: &str = "TXWhjswto9q6hfaGPuAhDS79wAHKfbMJLVR178xYAaQ";
const DEFAULT_GENERIC_BUFFER: &str = "GBYLmevzPSBPWfWrJ1h9gNzHqUjDXETzHKL1AasLyKwC";
const DEFAULT_MANUAL_CLAIM: &str = "MCdYbqiK3uj36tohbMjsh3Ssg8iRSJmSHToNxW8TWWE";
const DEFAULT_NOOP_SHIM: &str = "FwDChsHWLwbhTiYQ4Sum5mjVWswECi9cmrA11GUFUuxi";

#[derive(Debug, Parser)]
#[command(
    name = "init-bridge",
    about = "Create the DOGE SPL mint and initialize the doge-bridge program state"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    solana_rpc_url: String,
    #[arg(long)]
    operator_keypair: PathBuf,
    #[arg(long)]
    payer_keypair: PathBuf,
    #[arg(long, default_value = DEFAULT_DOGE_BRIDGE)]
    doge_bridge_program: Pubkey,
    #[arg(long)]
    recipient_keypair: Option<PathBuf>,
    #[arg(long)]
    doge_mint_keypair: Option<PathBuf>,
}

fn read_keypair(path: &PathBuf, role: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|e| anyhow::anyhow!("read {role} keypair {}: {e}", path.display()))
}

fn clone_keypair(keypair: &Keypair) -> Result<Keypair> {
    Keypair::from_bytes(&keypair.to_bytes()).context("clone Solana keypair")
}

fn bridge_state_pda(program_id: Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"bridge_state"], &program_id).0
}

fn default_initialize_params() -> InitializeBridgeParams {
    InitializeBridgeParams {
        bridge_header: PsyBridgeHeader::default(),
        custodian_wallet_config_hash: [1u8; 32],
        start_return_txo_output: PsyReturnTxOutput {
            sighash: [0; 32],
            output_index: 0,
            amount_sats: 0,
        },
        config_params: PsyBridgeConfig {
            deposit_fee_rate_numerator: 0,
            deposit_fee_rate_denominator: 100,
            withdrawal_fee_rate_numerator: 2,
            withdrawal_fee_rate_denominator: 100,
            deposit_flat_fee_sats: 0,
            withdrawal_flat_fee_sats: 1000,
        },
    }
}

async fn create_doge_mint_if_needed(
    rpc: &RpcClient,
    payer: &Keypair,
    mint_keypair: &Keypair,
    mint_authority: &Pubkey,
) -> Result<()> {
    let mint = mint_keypair.pubkey();
    if rpc.get_account(&mint).await.is_ok() {
        return Ok(());
    }

    let rent = rpc
        .get_minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN)
        .await
        .context("mint rent exemption")?;

    let create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &mint,
        rent,
        spl_token::state::Mint::LEN as u64,
        &spl_token::id(),
    );

    let init_ix =
        spl_token::instruction::initialize_mint(&spl_token::id(), &mint, mint_authority, None, 8)
            .context("initialize_mint instruction")?;

    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = Transaction::new_signed_with_payer(
        &[create_ix, init_ix],
        Some(&payer.pubkey()),
        &[payer, mint_keypair],
        blockhash,
    );
    rpc.send_and_confirm_transaction(&tx)
        .await
        .context("create DOGE mint transaction")?;
    Ok(())
}

async fn ensure_recipient_ata(
    rpc: &RpcClient,
    payer: &Keypair,
    owner: &Pubkey,
    doge_mint: &Pubkey,
) -> Result<Pubkey> {
    let ata = get_associated_token_address(owner, doge_mint);
    if rpc.get_account(&ata).await.is_ok() {
        return Ok(ata);
    }

    let ix = create_associated_token_account(&payer.pubkey(), owner, doge_mint, &spl_token::id());
    let blockhash = rpc.get_latest_blockhash().await?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[payer], blockhash);
    rpc.send_and_confirm_transaction(&tx)
        .await
        .context("create recipient ATA")?;
    Ok(ata)
}

#[tokio::main]
async fn main() -> Result<()> {
    run(Args::parse()).await
}

async fn run(args: Args) -> Result<()> {
    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;

    let bridge_state = bridge_state_pda(args.doge_bridge_program);
    if args.doge_bridge_program != Pubkey::from_str(DEFAULT_DOGE_BRIDGE)? {
        eprintln!(
            "warning: doge-bridge-client initialize instruction uses the compiled default program id; \
             ensure it matches --doge-bridge-program ({})",
            args.doge_bridge_program
        );
    }

    let mint_keypair = match &args.doge_mint_keypair {
        Some(path) => read_keypair(path, "doge mint")?,
        None => Keypair::new(),
    };
    let doge_mint = mint_keypair.pubkey();

    let rpc =
        RpcClient::new_with_commitment(args.solana_rpc_url.clone(), CommitmentConfig::confirmed());

    create_doge_mint_if_needed(&rpc, &payer, &mint_keypair, &bridge_state).await?;

    let client_config = BridgeClientConfigBuilder::new()
        .rpc_url(args.solana_rpc_url.clone())
        .bridge_state_pda(bridge_state)
        .operator(clone_keypair(&operator)?)
        .payer(clone_keypair(&payer)?)
        .program_id(args.doge_bridge_program)
        .pending_mint_program_id(Pubkey::from_str(DEFAULT_PENDING_MINT)?)
        .txo_buffer_program_id(Pubkey::from_str(DEFAULT_TXO_BUFFER)?)
        .generic_buffer_program_id(Pubkey::from_str(DEFAULT_GENERIC_BUFFER)?)
        .manual_claim_program_id(Pubkey::from_str(DEFAULT_MANUAL_CLAIM)?)
        .wormhole_core_program_id(Pubkey::from_str(DEFAULT_NOOP_SHIM)?)
        .wormhole_shim_program_id(Pubkey::from_str(DEFAULT_NOOP_SHIM)?)
        .doge_mint(doge_mint)
        .build()
        .context("build bridge client configuration")?;

    let bridge_client = BridgeClient::with_config(client_config).context("create bridge client")?;

    if rpc.get_account(&bridge_state).await.is_ok() {
        bail!(
            "bridge state account already exists at {bridge_state}; initialize can only run once"
        );
    }

    let params = default_initialize_params();
    let init_sig = bridge_client
        .initialize_bridge(&params)
        .await
        .context("initialize_bridge")?;

    let mut recipient_ata: Option<Pubkey> = None;
    if let Some(path) = &args.recipient_keypair {
        let recipient = read_keypair(path, "recipient")?;
        let owner = recipient.pubkey();
        recipient_ata = Some(ensure_recipient_ata(&rpc, &payer, &owner, &doge_mint).await?);
    }

    println!("bridge_state_pda: {bridge_state}");
    println!("doge_mint: {doge_mint}");
    println!("initialize_signature: {init_sig}");
    if let Some(ata) = recipient_ata {
        println!("recipient_token_account: {ata}");
    }

    Ok(())
}
