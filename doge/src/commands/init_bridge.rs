//! One-shot CLI: create DOGE SPL mint (bridge PDA as authority) and initialize the bridge.

use anyhow::{bail, Context, Result};
use clap::Parser;
use crate::network::{fill_string, RuntimeNetwork};
use doge_bridge_client::{
    BridgeApi, BridgeClient, BridgeClientConfigBuilder, OperatorApi, PsyBridgeConfig,
    PsyBridgeHeader, PsyReturnTxOutput,
};
use psy_doge_solana_core::instructions::doge_bridge::{
    InitializeBridgeInstructionDataDoge, InitializeBridgeParams,
};
use psy_doge_bridge_helper::tx_template::{
    CustodyScriptConfig, ManagerCustodyProfile, OfficialTestnetManagerCustody,
};
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

const DEFAULT_DOGE_BRIDGE: &str = "9HdfoY6yYFLo3sQ5qMv9tHHgXzB3AnA2GXXyedeWrLdN";
const DEFAULT_PENDING_MINT: &str = "DHB58D8HbnRM7QQiJ37iE3YjCfUbzbhpcc2Bf5rAXkua";
const DEFAULT_TXO_BUFFER: &str = "9N217cCfEhickevyD3amY1BQh8P8Hay7CKKWa5kgrgHs";
const DEFAULT_GENERIC_BUFFER: &str = "marxYjRRhMAmfyGPNwkKEgwzKsSNfmKQ4gzMLadZxuz";
const DEFAULT_MANUAL_CLAIM: &str = "BsMpUmLvjjkvgrmQWJeaitmbQx1L5uXi5woXBbuDyUBJ";
// The expected devnet custodian wallet config hash is derived dynamically from
// the current doge-bridge program Bridge State PDA, the official Wormhole
// Testnet Manager set 1 keys, config_id 1, and network_type 0 via
// `CustodyScriptConfig::hash::<OfficialTestnetManagerCustody>`. The PDA is not
// pinned to a retired deployment, so a fresh program identity derives the
// canonical profile hash for its own Bridge State PDA.

#[derive(Debug, Parser)]
#[command(
    name = "init-bridge",
    about = "Create the DOGE SPL mint and initialize bridge state from explicit Dogecoin data",
    long_about = "Creates the DOGE SPL mint and initializes bridge state. Runtime RPC and Wormhole programs come from global --network. Devnet requires --doge-config and --doge-mint-keypair so public initialization cannot use localhost defaults or an ephemeral mint identity."
)]
pub struct Args {
    /// Captured global runtime network for public-initialization safety checks.
    #[arg(skip)]
    runtime_network: RuntimeNetwork,
    #[arg(long, help = "Solana RPC URL override")]
    solana_rpc_url: Option<String>,
    #[arg(long)]
    operator_keypair: PathBuf,
    #[arg(long)]
    payer_keypair: PathBuf,
    #[arg(skip = Pubkey::from_str_const(DEFAULT_DOGE_BRIDGE))]
    doge_bridge_program: Pubkey,
    #[arg(long)]
    recipient_keypair: Option<PathBuf>,
    #[arg(long)]
    doge_mint_keypair: Option<PathBuf>,
    #[arg(
        long,
        help = "InitializeBridgeInstructionDataDoge JSON; required on devnet"
    )]
    doge_config: Option<PathBuf>,
    #[arg(long, help = "Wormhole Core / noop program override")]
    wormhole_core_program: Option<Pubkey>,
    #[arg(long, help = "Wormhole Shim / noop program override")]
    wormhole_shim_program: Option<Pubkey>,
}

impl Args {
    pub fn apply_network_defaults(&mut self, network: RuntimeNetwork) {
        self.runtime_network = network;
        let defaults = network.defaults();
        fill_string(&mut self.solana_rpc_url, defaults.solana_rpc_url);
        if self.wormhole_core_program.is_none() {
            self.wormhole_core_program =
                Some(defaults.wormhole_core_program.parse().expect("wormhole core"));
        }
        if self.wormhole_shim_program.is_none() {
            self.wormhole_shim_program =
                Some(defaults.wormhole_shim_program.parse().expect("wormhole shim"));
        }
    }

    fn solana_rpc_url(&self) -> &str {
        self.solana_rpc_url
            .as_deref()
            .expect("solana_rpc_url requires apply_network_defaults")
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
        self.runtime_network.validate_wormhole_programs(
            &self.wormhole_core_program().to_string(),
            &self.wormhole_shim_program().to_string(),
        )
    }
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
fn initialize_params(args: &Args) -> Result<InitializeBridgeParams> {
    if let Some(path) = &args.doge_config {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read Dogecoin initialization data {}", path.display()))?;
        let data: InitializeBridgeInstructionDataDoge = serde_json::from_slice(&bytes)
            .with_context(|| {
                format!(
                    "parse {} as InitializeBridgeInstructionDataDoge JSON",
                    path.display()
                )
            })?;
        if matches!(args.runtime_network, RuntimeNetwork::Devnet) {
            // Validate the supplied config hash against the canonical hash
            // derived from the *current* doge-bridge Bridge State PDA and the
            // official Wormhole Testnet Manager set 1 (config_id 1,
            // network_type 0). The manager keys come from the compile-time
            // OfficialTestnetManagerCustody profile; we additionally cross-check
            // those profile keys against the deployed set bytes so a profile
            // drift is caught before public initialization.
            let emitter = bridge_state_pda(args.doge_bridge_program);
            let manager_set = crate::wormhole::manager::official_testnet_manager_set_1()
                .context("parse official testnet manager set 1")?;
            let custody_config = CustodyScriptConfig::try_from_manager_set::<OfficialTestnetManagerCustody>(
                emitter.to_bytes(),
                manager_set.m,
                &manager_set.pubkeys,
                OfficialTestnetManagerCustody::CONFIG_ID,
            )
            .context("official testnet manager set 1 does not match the custody profile")?;
            let expected = custody_config.hash::<OfficialTestnetManagerCustody>();
            if data.custodian_wallet_config_hash != expected {
                bail!(
                    "--network devnet requires official Dogecoin Manager set 1 config hash {} for bridge PDA {}; got {}",
                    hex::encode(expected),
                    emitter,
                    hex::encode(data.custodian_wallet_config_hash),
                );
            }
        }
        return Ok(InitializeBridgeParams {
            bridge_header: data.bridge_header,
            start_return_txo_output: data.start_return_txo_output,
            config_params: data.config_params,
            custodian_wallet_config_hash: data.custodian_wallet_config_hash,
        });
    }
    if !args.runtime_network.is_localhost() {
        bail!("--doge-config is required with --network devnet; localhost defaults are forbidden on public state");
    }
    Ok(default_initialize_params())
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

pub async fn run(args: Args) -> Result<()> {
    args.validate_network_boundary()?;
    if !args.runtime_network.is_localhost() && args.doge_mint_keypair.is_none() {
        bail!("--doge-mint-keypair is required with --network devnet; an ephemeral public mint identity is forbidden");
    }
    let params = initialize_params(&args)?;
    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;

    let bridge_state = bridge_state_pda(args.doge_bridge_program);

    let rpc =
        RpcClient::new_with_commitment(args.solana_rpc_url().to_owned(), CommitmentConfig::confirmed());
    if rpc.get_account(&bridge_state).await.is_ok() {
        bail!(
            "bridge state account already exists at {bridge_state}; initialize can only run once"
        );
    }

    let mint_keypair = match &args.doge_mint_keypair {
        Some(path) => read_keypair(path, "doge mint")?,
        None => Keypair::new(),
    };
    let doge_mint = mint_keypair.pubkey();
    create_doge_mint_if_needed(&rpc, &payer, &mint_keypair, &bridge_state).await?;

    let client_config = BridgeClientConfigBuilder::new()
        .rpc_url(args.solana_rpc_url().to_owned())
        .bridge_state_pda(bridge_state)
        .operator(clone_keypair(&operator)?)
        .payer(clone_keypair(&payer)?)
        .program_id(args.doge_bridge_program)
        .pending_mint_program_id(Pubkey::from_str(DEFAULT_PENDING_MINT)?)
        .txo_buffer_program_id(Pubkey::from_str(DEFAULT_TXO_BUFFER)?)
        .generic_buffer_program_id(Pubkey::from_str(DEFAULT_GENERIC_BUFFER)?)
        .manual_claim_program_id(Pubkey::from_str(DEFAULT_MANUAL_CLAIM)?)
        .wormhole_core_program_id(args.wormhole_core_program())
        .wormhole_shim_program_id(args.wormhole_shim_program())
        .doge_mint(doge_mint)
        .build()
        .context("build bridge client configuration")?;

    let bridge_client = BridgeClient::with_config(client_config).context("create bridge client")?;

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
