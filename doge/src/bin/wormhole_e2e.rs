//! End-to-end Wormhole relay plumbing test: build a `UTX0` unlock payload,
//! encode/decode round-trip, build the redeem script, and (optionally) probe
//! the guardian manager-service API for connectivity.
//!
//! Run:
//!   wormhole_e2e
//!   wormhole_e2e --manager-api https://wormhole-v2-testnet-api.crosschainibc.com \
//!                --emitter-hex 3b26...ca98 --sequence 1

use anyhow::{Context, Result};
use clap::Parser;
use doge_local_ops::wormhole::{
    manager::{fetch_manager_signatures, local_regtest_manager_set},
    redeem::build_redeem_script,
    utx0::{Utx0Input, Utx0Output, Utx0UnlockPayload, UtxoAddressType},
};

#[derive(Debug, Parser)]
#[command(
    name = "wormhole-e2e",
    about = "Wormhole UTX0 + redeem script end-to-end smoke test"
)]
struct Args {
    /// Emitter hex (32 bytes) used for the redeem script + optional API probe.
    #[arg(
        long,
        default_value = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    )]
    emitter_hex: String,
    /// VAA sequence number for the optional API probe.
    #[arg(long, default_value_t = 0)]
    sequence: u64,
    /// Emitter Wormhole chain ID (Solana = 1).
    #[arg(long, default_value_t = 1)]
    emitter_chain: u16,
    /// Optional guardian manager-service API base URL for a connectivity probe.
    #[arg(long)]
    manager_api: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let emitter = hex::decode(&args.emitter_hex)
        .with_context(|| format!("decode emitter hex {}", args.emitter_hex))?;
    let emitter: [u8; 32] = emitter
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("emitter must be 32 bytes"))?;

    // ── Build a sample UTX0 unlock payload ──
    let recipient = {
        let mut r = [0u8; 32];
        hex::decode_to_slice(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            &mut r,
        )?;
        r
    };
    let txid = {
        let mut t = [0u8; 32];
        hex::decode_to_slice(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            &mut t,
        )?;
        t
    };

    let payload = Utx0UnlockPayload {
        destination_chain: doge_local_ops::wormhole::chain_id::DOGECOIN,
        delegated_manager_set_index: 0,
        inputs: vec![Utx0Input {
            original_recipient_address: recipient,
            transaction_id: txid,
            vout: 0,
        }],
        outputs: vec![Utx0Output {
            amount: 1_000_000,
            address_type: UtxoAddressType::P2pkh,
            address: hex::decode("55ae51684c43435da751ac8d2173b2652eb64105")?,
        }],
    };

    // ── Encode / decode round-trip ──
    let encoded = payload.serialize()?;
    let decoded = Utx0UnlockPayload::parse(&encoded)?;
    assert_eq!(decoded, payload, "UTX0 round-trip mismatch");
    println!("UTX0 round-trip OK: {} bytes", encoded.len());
    println!("UTX0 hex: {}", hex::encode(&encoded));

    // ── Redeem script with the deterministic local-regtest 5/7 manager set ──
    let ms = local_regtest_manager_set();
    let redeem = build_redeem_script(args.emitter_chain, &emitter, &recipient, ms.m, &ms.pubkeys)?;
    println!(
        "redeem script (m={}, n={}, {} bytes): {}",
        ms.m,
        ms.n,
        redeem.len(),
        hex::encode(&redeem)
    );

    // ── Optional manager API connectivity probe ──
    if let Some(base) = args.manager_api {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        match fetch_manager_signatures(&client, &base, args.emitter_chain, &emitter, args.sequence)
            .await
        {
            Ok(msig) => {
                println!(
                    "manager API reachable: isComplete={}, signers={}, required={}/{}, vaaId={}",
                    msig.is_complete,
                    msig.signatures.len(),
                    msig.required,
                    msig.total,
                    msig.vaa_id,
                );
            }
            Err(e) => {
                println!("manager API probe failed (non-fatal): {e}");
            }
        }
    }

    println!("wormhole_e2e OK");
    Ok(())
}
