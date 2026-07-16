use anyhow::{anyhow, bail, Context, Result};
use bitcoin::{
    absolute,
    consensus::encode::serialize_hex,
    ecdsa,
    hashes::Hash as BitcoinHash,
    script::Builder,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction, Address, Amount, BlockHash, Network, OutPoint, PrivateKey, ScriptBuf, ScriptHash,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bs58;
use clap::{Parser, ValueEnum};
use doge_bridge_client::operator_store::{CustodyUtxo, CustodyUtxoStatus, OperatorStore};
use doge_bridge_client::{BridgeApi, BridgeClient, BridgeClientConfigBuilder};
use doge_local_ops::wormhole::{manager::local_regtest_manager_set, redeem::build_redeem_script};
use doge_local_ops::{custody_ops, SATS_PER_DOGE};
use reqwest::Client as HttpClient;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair},
};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::time::sleep;

const DEFAULT_DOGE_BRIDGE: &str = "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ";
const DEFAULT_NOOP_SHIM: &str = "FwDChsHWLwbhTiYQ4Sum5mjVWswECi9cmrA11GUFUuxi";
const DEFAULT_CUSTODY_KEY_REFERENCE: &str = "bridge-custody-wallet#0";
const DEFAULT_FEE_SATS: u64 = 1_000_000;
const DOGE_DUST_LIMIT_SATS: u64 = SATS_PER_DOGE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NetworkProfile {
    Regtest,
    Testnet,
}

impl NetworkProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet => "testnet",
        }
    }

    fn bitcoin_network(self) -> Network {
        match self {
            Self::Regtest => Network::Regtest,
            Self::Testnet => Network::Testnet,
        }
    }

    fn p2pkh_version(self) -> u8 {
        match self {
            Self::Regtest => 0x6f,
            Self::Testnet => 0x71,
        }
    }

    fn wif_version(self) -> u8 {
        match self {
            Self::Regtest => 0xef,
            Self::Testnet => 0xf1,
        }
    }

    fn encode_address(self, address_type: u32, payload: [u8; 20]) -> Result<String> {
        let version = match address_type {
            0 => self.p2pkh_version(),
            1 => 0xc4,
            other => bail!("unsupported Dogecoin address type {other}"),
        };
        let mut bytes = Vec::with_capacity(21);
        bytes.push(version);
        bytes.extend_from_slice(&payload);
        Ok(bs58::encode(bytes).with_check().into_string())
    }

    fn validate_wif(self, wif: &str) -> Result<()> {
        let decoded = bs58::decode(wif).with_check(None).into_vec()?;
        if decoded.len() != 33 && decoded.len() != 34 {
            bail!("Dogecoin WIF payload must be 33 or 34 bytes, got {}", decoded.len());
        }
        if decoded[0] != self.wif_version() {
            bail!(
                "WIF version 0x{:02x} does not match {} (expected 0x{:02x})",
                decoded[0],
                self.as_str(),
                self.wif_version(),
            );
        }
        if decoded.len() == 34 && decoded[33] != 1 {
            bail!("compressed Dogecoin WIF is missing the 0x01 marker");
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "deposit-to-solana",
    about = "Send a Dogecoin deposit to bridge custody and register its confirmed UTXO",
    long_about = "Derives the recipient-specific P2SH custody address, builds and signs one legacy Dogecoin funding transaction, broadcasts it through Electrs, passively waits for confirmation, registers the confirmed custody UTXO, and writes deposit evidence.",
    after_long_help = "Select --network regtest (default) or --network testnet. Testnet validates P2PKH 0x71, P2SH 0xc4 and WIF 0xf1, and uses passive Electrs confirmation without dogecoind or mining. The WIF is never written to evidence."
)]
struct Args {
    #[arg(long, value_enum, default_value_t = NetworkProfile::Regtest)]
    network: NetworkProfile,
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
    #[arg(long, default_value = DEFAULT_NOOP_SHIM)]
    noop_shim_program: Pubkey,
    #[arg(long)]
    bridge_state: Option<Pubkey>,
    #[arg(long, default_value = "http://127.0.0.1:3002")]
    electrs_url: String,
    #[arg(long)]
    funding_wif: String,
    #[arg(long)]
    funding_txid: Txid,
    #[arg(long)]
    funding_vout: u32,
    #[arg(long, help = "Exact value in satoshis of the explicit funding UTXO")]
    funding_amount: u64,
    #[arg(long, default_value_t = SATS_PER_DOGE)]
    amount_sats: u64,
    #[arg(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u32).range(1..),
        help = "Deprecated compatibility option; ignored because mining is external"
    )]
    mine_blocks: u32,
    #[arg(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u64).range(1..),
        help = "Deprecated compatibility option; ignored; the CLI waits for the first confirmation"
    )]
    min_confirmations: u64,
    #[arg(long, default_value_t = 120)]
    confirmation_timeout_secs: u64,
    #[arg(long, default_value_t = 500)]
    poll_interval_ms: u64,
    #[arg(long, default_value = DEFAULT_CUSTODY_KEY_REFERENCE)]
    custody_key_reference: String,
    #[arg(long)]
    operator_store: PathBuf,
    #[arg(long, default_value = "/tmp/doge-deposit-to-solana-evidence.json")]
    evidence_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ElectrsUtxo {
    txid: Txid,
    vout: u32,
    value: u64,
    status: ElectrsTxStatus,
}

#[derive(Debug, Clone, Deserialize)]
struct ElectrsTxStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
    block_time: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ElectrsTx {
    txid: Txid,
    vout: Vec<ElectrsVout>,
    status: ElectrsTxStatus,
}

#[derive(Debug, Deserialize)]
struct ElectrsVout {
    scriptpubkey: String,
    value: u64,
}

#[derive(Serialize)]
struct Evidence {
    schema: &'static str,
    completed: bool,
    deposit: Value,
    custody: Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    run(Args::parse()).await
}

async fn run(args: Args) -> Result<()> {
    if args.amount_sats < DOGE_DUST_LIMIT_SATS {
        bail!(
            "--amount-sats must be at least the Dogecoin dust limit of {DOGE_DUST_LIMIT_SATS} sats"
        );
    }
    let _compatibility_only = (args.mine_blocks, args.min_confirmations);

    let operator = read_keypair(&args.operator_keypair, "operator")?;
    let payer = read_keypair(&args.payer_keypair, "payer")?;
    let (derived_bridge_state, _) =
        Pubkey::find_program_address(&[b"bridge_state"], &args.doge_bridge_program);
    if let Some(provided) = args.bridge_state {
        if provided != derived_bridge_state {
            bail!("--bridge-state {provided} does not match derived PDA {derived_bridge_state}");
        }
    }

    let bridge_client = BridgeClient::with_config(
        BridgeClientConfigBuilder::new()
            .rpc_url(args.solana_rpc_url.clone())
            .bridge_state_pda(derived_bridge_state)
            .operator(clone_keypair(&operator)?)
            .payer(clone_keypair(&payer)?)
            .program_id(args.doge_bridge_program)
            .wormhole_core_program_id(args.noop_shim_program)
            .wormhole_shim_program_id(args.noop_shim_program)
            .build()
            .context("build bridge client configuration")?,
    )
    .context("create bridge client")?;
    bridge_client
        .get_current_bridge_state()
        .await
        .context("read initialized bridge state")?;

    let store = OperatorStore::open(&args.operator_store).context("open operator store")?;
    let (deposit_address, script_hash) = p2sh_custody_address(
        args.network,
        &derived_bridge_state,
        &args.recipient_token_account,
    )?;
    let manager_set = local_regtest_manager_set();
    let redeem_script = build_redeem_script(
        1,
        &derived_bridge_state.to_bytes(),
        &args.recipient_token_account.to_bytes(),
        manager_set.m,
        &manager_set.pubkeys,
    )?;
    eprintln!(
        "P2SH custody deposit address: {deposit_address}\nredeem script ({} bytes): {}\nscript_hash: {}",
        redeem_script.len(),
        hex::encode(&redeem_script),
        hex::encode(script_hash),
    );

    args.network
        .validate_wif(&args.funding_wif)
        .context("validate --funding-wif network")?;
    let funding_key = PrivateKey::from_wif(&args.funding_wif).context("parse --funding-wif")?;
    if funding_key.network != args.network.bitcoin_network() {
        bail!("--funding-wif does not match {}", args.network.as_str());
    }
    let secp = Secp256k1::new();
    let funding_public_key = funding_key.public_key(&secp);
    let funding_address = Address::p2pkh(&funding_public_key, args.network.bitcoin_network());
    let funding_script = funding_address.script_pubkey();
    let deposit_script = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(script_hash));
    let rust_dogecoin_deposit_address =
        Address::from_script(&deposit_script, args.network.bitcoin_network())
            .context("derive rust-dogecoin P2SH address")?;
    if rust_dogecoin_deposit_address.to_string() != deposit_address {
        bail!(
            "P2SH address mismatch: bridge derivation produced {deposit_address}, rust-dogecoin produced {rust_dogecoin_deposit_address}"
        );
    }

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build Electrs HTTP client")?;
    verify_funding_utxo(
        &http,
        args.network,
        &args.electrs_url,
        &funding_address.to_string(),
        args.funding_txid,
        args.funding_vout,
        args.funding_amount,
    )
    .await?;

    let (deposit_tx, fee_sats) = build_signed_deposit_transaction(
        &secp,
        funding_key,
        funding_public_key,
        funding_script,
        args.funding_txid,
        args.funding_vout,
        args.funding_amount,
        deposit_script.clone(),
        args.amount_sats,
    )?;
    let local_txid = deposit_tx.txid();
    let raw_tx_hex = serialize_hex(&deposit_tx);
    let broadcast_txid = broadcast_electrs(&http, &args.electrs_url, &raw_tx_hex).await?;
    if broadcast_txid != local_txid {
        bail!("Electrs returned txid {broadcast_txid}, but rust-dogecoin constructed {local_txid}");
    }
    write_evidence(
        &args.evidence_path,
        &Evidence {
            schema: "doge-custody-deposit-evidence-v2",
            completed: false,
            deposit: json!({
                "network": args.network.as_str(),
                "electrs_url": args.electrs_url,
                "funding_address": funding_address.to_string(),
                "funding_txid": args.funding_txid.to_string(),
                "funding_vout": args.funding_vout,
                "funding_amount_sats": args.funding_amount,
                "deposit_address": deposit_address,
                "txid": local_txid.to_string(),
                "amount_sats": args.amount_sats,
                "fee_sats": fee_sats,
                "raw_transaction_hex": raw_tx_hex,
                "status": "BROADCAST_PENDING_CONFIRMATION",
            }),
            custody: json!({
                "registered": false,
                "operator_store": args.operator_store,
                "bridge_state": derived_bridge_state.to_string(),
                "recipient_token_account": args.recipient_token_account.to_string(),
                "original_recipient_address_hex": hex::encode(args.recipient_token_account.to_bytes()),
                "key_reference": args.custody_key_reference,
                "redeem_script_hex": hex::encode(&redeem_script),
                "script_hash_hex": hex::encode(script_hash),
            }),
        },
    )?;

    let confirmed = poll_deposit(
        &http,
        &args.electrs_url,
        local_txid,
        Duration::from_secs(args.confirmation_timeout_secs),
        Duration::from_millis(args.poll_interval_ms),
    )
    .await?;
    if confirmed.txid != local_txid {
        bail!(
            "Electrs returned transaction {} while polling {local_txid}",
            confirmed.txid
        );
    }

    let expected_script_pubkey_hex = hex::encode(deposit_script.as_bytes());
    let (deposit_vout, deposit_sats, script_pubkey_hex) = confirmed
        .vout
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            output.value == args.amount_sats
                && output
                    .scriptpubkey
                    .eq_ignore_ascii_case(&expected_script_pubkey_hex)
        })
        .try_fold(None, |found, (index, output)| {
            if found.is_some() {
                bail!("confirmed transaction has multiple matching custody outputs");
            }
            Ok::<_, anyhow::Error>(Some((
                u32::try_from(index).context("deposit vout exceeds u32")?,
                output.value,
                output.scriptpubkey.clone(),
            )))
        })?
        .ok_or_else(|| {
            anyhow!("confirmed transaction does not contain the expected custody output")
        })?;

    let status = confirmed.status;
    let block_height = status
        .block_height
        .ok_or_else(|| anyhow!("confirmed Electrs transaction is missing block_height"))?;
    let block_hash_text = status
        .block_hash
        .ok_or_else(|| anyhow!("confirmed Electrs transaction is missing block_hash"))?;
    let block_hash =
        BlockHash::from_str(&block_hash_text).context("parse confirmation block hash")?;
    let block_txids: Vec<Txid> = electrs_get_json(
        &http,
        format!(
            "{}/block/{block_hash_text}/txids",
            args.electrs_url.trim_end_matches('/')
        ),
    )
    .await?;
    let tx_index = block_txids
        .iter()
        .position(|txid| *txid == local_txid)
        .ok_or_else(|| {
            anyhow!("deposit transaction is absent from its confirmation block txids")
        })?;
    let tx_index =
        u16::try_from(tx_index).context("deposit block transaction index exceeds u16")?;
    let tip_height = electrs_get_height(&http, &args.electrs_url).await?;
    let confirmations = tip_height
        .checked_sub(block_height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or_else(|| {
            anyhow!("Electrs tip height {tip_height} precedes deposit height {block_height}")
        })?;
    let deposit_vout_u16 = u16::try_from(deposit_vout).context("deposit vout exceeds u16")?;
    let leaf_index = custody_ops::compute_combined_index(block_height, tx_index, deposit_vout_u16);

    let txid_bytes = local_txid.to_byte_array();
    let custody_utxo = CustodyUtxo {
        txid: txid_bytes,
        vout: deposit_vout,
        amount_sats: deposit_sats,
        script_pubkey_hex: script_pubkey_hex.clone(),
        custody_address: deposit_address.clone(),
        key_reference: args.custody_key_reference.clone(),
        confirmation_block_hash: Some(block_hash.to_byte_array()),
        confirmation_height: Some(block_height),
        confirmations,
        leaf_index,
        status: CustodyUtxoStatus::Available,
        reservation_id: None,
        spend_txid: None,
        source_deposit_txid: Some(txid_bytes),
        source_solana_signature: None,
        spend_request_index: None,
        spend_process_signature: None,
        original_recipient_address: args.recipient_token_account.to_bytes(),
    };
    store
        .upsert_custody_utxo(&custody_utxo)
        .context("register deposit custody UTXO")?;

    let evidence = Evidence {
        schema: "doge-custody-deposit-evidence-v2",
        completed: true,
        deposit: json!({
            "network": args.network.as_str(),
            "electrs_url": args.electrs_url,
            "funding_address": funding_address.to_string(),
            "funding_txid": args.funding_txid.to_string(),
            "funding_vout": args.funding_vout,
            "funding_amount_sats": args.funding_amount,
            "deposit_address": deposit_address,
            "txid": local_txid.to_string(),
            "vout": deposit_vout,
            "amount_sats": deposit_sats,
            "fee_sats": fee_sats,
            "confirmations": confirmations,
            "confirmation_block_hash": block_hash_text,
            "confirmation_height": block_height,
            "confirmation_block_time": status.block_time,
            "transaction_index": tx_index,
            "raw_transaction_hex": raw_tx_hex,
        }),
        custody: json!({
            "registered": true,
            "operator_store": args.operator_store,
            "bridge_state": derived_bridge_state.to_string(),
            "recipient_token_account": args.recipient_token_account.to_string(),
            "original_recipient_address_hex": hex::encode(args.recipient_token_account.to_bytes()),
            "key_reference": args.custody_key_reference,
            "script_pubkey_hex": script_pubkey_hex,
            "redeem_script_hex": hex::encode(redeem_script),
            "script_hash_hex": hex::encode(script_hash),
            "leaf_index": leaf_index,
        }),
    };
    write_evidence(&args.evidence_path, &evidence)?;
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    println!("Deposit sent. IBC pipeline will detect the new block and submit block_update automatically.");
    Ok(())
}

fn build_signed_deposit_transaction(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    funding_key: PrivateKey,
    funding_public_key: bitcoin::PublicKey,
    funding_script: ScriptBuf,
    funding_txid: Txid,
    funding_vout: u32,
    funding_amount: u64,
    deposit_script: ScriptBuf,
    amount_sats: u64,
) -> Result<(Transaction, u64)> {
    let required = amount_sats
        .checked_add(DEFAULT_FEE_SATS)
        .ok_or_else(|| anyhow!("deposit amount plus fee overflows u64"))?;
    let change_sats = funding_amount.checked_sub(required).ok_or_else(|| {
        anyhow!(
            "funding UTXO contains {funding_amount} sats, but deposit plus fee requires {required} sats"
        )
    })?;
    if change_sats != 0 && change_sats < DOGE_DUST_LIMIT_SATS {
        bail!(
            "funding change would be {change_sats} sats, below the Dogecoin dust limit of {DOGE_DUST_LIMIT_SATS}; provide an exact or larger funding UTXO"
        );
    }

    let mut outputs = Vec::with_capacity(if change_sats == 0 { 1 } else { 2 });
    outputs.push(TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: deposit_script,
    });
    if change_sats != 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: funding_script.clone(),
        });
    }

    let mut transaction = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: funding_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: outputs,
    };
    let sighash = SighashCache::new(&transaction)
        .legacy_signature_hash(0, &funding_script, EcdsaSighashType::All.to_u32())
        .context("compute funding P2PKH sighash")?;
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = ecdsa::Signature::sighash_all(secp.sign_ecdsa(&message, &funding_key.inner));
    transaction.input[0].script_sig = Builder::new()
        .push_slice(signature.serialize())
        .push_key(&funding_public_key)
        .into_script();
    Ok((transaction, DEFAULT_FEE_SATS))
}

async fn verify_funding_utxo(
    client: &HttpClient,
    network: NetworkProfile,
    electrs_url: &str,
    funding_address: &str,
    funding_txid: Txid,
    funding_vout: u32,
    funding_amount: u64,
) -> Result<()> {
    Address::from_str(funding_address)
        .context("parse funding address for Electrs lookup")?
        .require_network(network.bitcoin_network())
        .with_context(|| format!("funding address is not {}", network.as_str()))?;
    let url = format!(
        "{}/address/{funding_address}/utxo",
        electrs_url.trim_end_matches('/'),
    );
    let utxos: Vec<ElectrsUtxo> = electrs_get_json(client, url).await?;
    let utxo = utxos
        .iter()
        .find(|utxo| utxo.txid == funding_txid && utxo.vout == funding_vout)
        .ok_or_else(|| {
            anyhow!(
                "funding outpoint {funding_txid}:{funding_vout} is not unspent at address {funding_address}"
            )
        })?;
    if utxo.value != funding_amount {
        bail!(
            "--funding-amount is {funding_amount} sats, but Electrs reports {} sats",
            utxo.value
        );
    }
    if !utxo.status.confirmed {
        bail!("funding outpoint {funding_txid}:{funding_vout} is not confirmed");
    }
    Ok(())
}

async fn broadcast_electrs(
    client: &HttpClient,
    electrs_url: &str,
    raw_tx_hex: &str,
) -> Result<Txid> {
    let url = format!("{}/tx", electrs_url.trim_end_matches('/'));
    let response = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(raw_tx_hex.to_owned())
        .send()
        .await
        .with_context(|| format!("broadcast Dogecoin transaction through {url}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("read Electrs broadcast response")?;
    if !status.is_success() {
        bail!("Electrs broadcast returned {status}: {body}");
    }
    Txid::from_str(body.trim().trim_matches('"')).context("parse Electrs broadcast txid")
}

async fn poll_deposit(
    client: &HttpClient,
    electrs_url: &str,
    txid: Txid,
    timeout: Duration,
    interval: Duration,
) -> Result<ElectrsTx> {
    let deadline = Instant::now() + timeout;
    let url = format!("{}/tx/{txid}", electrs_url.trim_end_matches('/'));
    let mut last_error = String::from("transaction has not reached Electrs");
    loop {
        match electrs_get_json::<ElectrsTx>(client, url.clone()).await {
            Ok(transaction) if transaction.status.confirmed => return Ok(transaction),
            Ok(_) => {
                last_error =
                    "transaction is not confirmed; external miner has not included it".into()
            }
            Err(error) => last_error = error.to_string(),
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for externally mined deposit {txid}: {last_error}");
        }
        sleep(interval).await;
    }
}

async fn electrs_get_height(client: &HttpClient, electrs_url: &str) -> Result<u32> {
    let url = format!("{}/blocks/tip/height", electrs_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("read {url}"))?;
    if !status.is_success() {
        bail!("Electrs GET {url} returned {status}: {body}");
    }
    body.trim()
        .parse::<u32>()
        .with_context(|| format!("parse Electrs tip height from {body:?}"))
}

async fn electrs_get_json<T: DeserializeOwned>(client: &HttpClient, url: String) -> Result<T> {
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("read {url}"))?;
    if !status.is_success() {
        bail!("Electrs GET {url} returned {status}: {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("decode Electrs response from {url}"))
}

fn p2sh_custody_address(
    network: NetworkProfile,
    bridge_state_pda: &Pubkey,
    recipient_token_account: &Pubkey,
) -> Result<(String, [u8; 20])> {
    let manager_set = local_regtest_manager_set();
    let redeem_script = build_redeem_script(
        1,
        &bridge_state_pda.to_bytes(),
        &recipient_token_account.to_bytes(),
        manager_set.m,
        &manager_set.pubkeys,
    )?;
    let script_hash: [u8; 20] = Ripemd160::digest(Sha256::digest(&redeem_script)).into();
    Ok((network.encode_address(1, script_hash)?, script_hash))
}

fn read_keypair(path: &Path, role: &str) -> Result<Keypair> {
    read_keypair_file(path)
        .map_err(|error| anyhow!("read {role} keypair {}: {error}", path.display()))
}

fn clone_keypair(keypair: &Keypair) -> Result<Keypair> {
    Keypair::from_bytes(&keypair.to_bytes()).context("clone Solana keypair")
}

fn write_evidence(path: &Path, evidence: &Evidence) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create evidence directory {}", parent.display()))?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(evidence)?)
        .with_context(|| format!("write {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("publish {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wif(profile: NetworkProfile, secret: u8) -> String {
        let mut payload = vec![profile.wif_version()];
        payload.extend_from_slice(&[secret; 32]);
        payload.push(1);
        bs58::encode(payload).with_check().into_string()
    }

    #[test]
    fn network_profiles_validate_dogecoin_wif_versions() {
        let regtest = wif(NetworkProfile::Regtest, 1);
        let testnet = wif(NetworkProfile::Testnet, 2);
        assert!(NetworkProfile::Regtest.validate_wif(&regtest).is_ok());
        assert!(NetworkProfile::Testnet.validate_wif(&regtest).is_err());
        assert!(NetworkProfile::Testnet.validate_wif(&testnet).is_ok());
        assert!(NetworkProfile::Regtest.validate_wif(&testnet).is_err());
    }

    #[test]
    fn network_profiles_encode_dogecoin_addresses() {
        let payload = [0x11; 20];
        assert_ne!(
            NetworkProfile::Regtest.encode_address(0, payload).unwrap(),
            NetworkProfile::Testnet.encode_address(0, payload).unwrap(),
        );
        assert_eq!(
            NetworkProfile::Regtest.encode_address(1, payload).unwrap(),
            NetworkProfile::Testnet.encode_address(1, payload).unwrap(),
        );
        assert_eq!(NetworkProfile::Testnet.p2pkh_version(), 0x71);
        assert_eq!(NetworkProfile::Testnet.wif_version(), 0xf1);
    }
}
