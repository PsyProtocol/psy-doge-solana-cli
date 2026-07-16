//! Relay-side withdrawal: collect M-of-N manager signatures for a Wormhole
//! `UTX0` unlock VAA, rebuild the Dogecoin transaction, verify the guardian
//! signatures, assemble the P2SH multisig `scriptSig`, and broadcast via
//! electrs.
//!
//! Flow (mirrors `wormhole/testing/dogecoin/withdraw-testnet.ts`):
//!   1. `fetch_manager_signatures` against the guardian manager-service API
//!      and poll until `isComplete`.
//!   2. Fetch the signed VAA via `fetch_signed_vaa` and verify its signing
//!      digest equals the manager-reported `vaaHash`, then parse it -> `UTX0`
//!      payload + emitter (do NOT trust `isComplete`).
//!   3. For every input, rebuild the redeem script
//!      (`emitter_chain || emitter_contract || OP_2DROP || recipient || OP_DROP || OP_M || pubkeys || OP_N || OP_CHECKMULTISIG`).
//!   4. Build the unsigned Dogecoin tx and compute SIGHASH_ALL sighashes.
//!   5. Verify each returned signature against its signer pubkey + sighash.
//!   6. For every input, assemble `OP_0 <sig_1>...<sig_M> <redeemScript>`.
//!   7. Serialize + broadcast via `POST /tx` to electrs; print the txid.
//!
//! Run:
//!   relay_withdrawal --guardian-rpc https://... --electrs-url https://doge-electrs-testnet-demo.qed.me \
//!                   --emitter-hex 3b26...ca98 --sequence 42 --manager-set-index 1

use std::{collections::HashSet, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use doge_local_ops::wormhole::{
    manager::{
        fetch_manager_signatures, fetch_signed_vaa, local_regtest_manager_set, parse_vaa,
        vaa_hash_matches, vaa_signing_digest, verify_manager_signature, ManagerSet,
        ManagerSignatures,
    },
    redeem::build_redeem_script,
    tx::UnsignedTransaction,
    utx0::Utx0UnlockPayload,
};
use tokio::time::sleep;

#[derive(Debug, Parser)]
#[command(
    name = "relay-withdrawal",
    about = "Relay a Wormhole UTX0 unlock VAA onto Dogecoin: fetch manager sigs, verify, broadcast.",
    long_about = "Relay a Wormhole UTX0 unlock VAA onto Dogecoin: fetch the signed VAA, verify guardian signatures, fetch and locally verify Manager signatures per input SIGHASH_ALL, assemble the P2SH multisig scriptSig, and broadcast via electrs.\n\nDefault mode is DRY-RUN: both --manager-signing-enabled and --broadcast-enabled default to false, so the relay only fetches/verifies pre-existing Manager signatures and prints the assembled signed transaction without broadcasting it. Pass --manager-signing-enabled to poll a live Manager service for signatures, and --broadcast-enabled to push the signed transaction to electrs."
)]
struct Args {
    /// Manager-service API base URL. The built-in manager set is local-regtest only.
    #[arg(long)]
    guardian_rpc: String,

    /// electrs base URL for `POST /tx` broadcast.
    #[arg(long)]
    electrs_url: String,

    /// Emitter contract address (32 bytes, hex, 0x-prefixed optional).
    #[arg(long)]
    emitter_hex: String,

    /// VAA sequence number to relay.
    #[arg(long)]
    sequence: u64,

    /// Emitter Wormhole chain ID (Solana = 1).
    #[arg(long, default_value_t = 1)]
    emitter_chain: u16,

    /// Delegated manager set index. `0` selects the deterministic local-regtest
    /// 5-of-7 fixture; public-network manager sets are not built in.
    #[arg(long, default_value_t = 0)]
    manager_set_index: u32,

    /// Poll interval (seconds) while waiting for signature aggregation.
    #[arg(long, default_value_t = 5)]
    poll_interval_secs: u64,

    /// Maximum total wait (seconds) for the signatures to complete.
    #[arg(long, default_value_t = 300)]
    timeout_secs: u64,

    /// Enable live Manager signing. When `false` (the default, dry-run mode)
    /// the relay performs a single Manager API fetch of whatever pre-existing
    /// signatures are already aggregated and verifies them locally — it never
    /// polls the service to wait for new signatures to arrive. Set `true` only
    /// for the full live flow against a signing Manager service.
    #[arg(long, default_value_t = false)]
    manager_signing_enabled: bool,

    /// Enable electrs broadcast. When `false` (the default, dry-run mode) the
    /// assembled signed transaction is printed but never sent to electrs; the
    /// relay stops after scriptSig assembly and local txid computation. Set
    /// `true` to actually push the transaction onto the Dogecoin network.
    #[arg(long, default_value_t = false)]
    broadcast_enabled: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let emitter = {
        let bytes = hex::decode(args.emitter_hex.trim_start_matches("0x"))
            .with_context(|| "decode emitter hex")?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("emitter must be 32 bytes"))?
    };

    let manager_set = resolve_manager_set(args.manager_set_index)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    // ── 1. Fetch manager signatures ──
    //
    // Dry-run (manager_signing_enabled=false): perform a single fetch of
    // whatever signatures the Manager service has already aggregated and
    // verify them locally — never poll for new signatures to arrive.
    // Full mode (manager_signing_enabled=true): poll until `isComplete`.
    let msig = if args.manager_signing_enabled {
        wait_for_signatures(
            &client,
            &args.guardian_rpc,
            args.emitter_chain,
            &emitter,
            args.sequence,
            args.poll_interval_secs,
            args.timeout_secs,
        )
        .await?
    } else {
        println!("[dry-run] manager signing skipped (manager_signing_enabled=false); fetching pre-existing signatures once");
        fetch_manager_signatures(
            &client,
            &args.guardian_rpc,
            args.emitter_chain,
            &emitter,
            args.sequence,
        )
        .await?
    };

    // ── 1b. Fetch signed VAA separately + verify join (do NOT trust isComplete) ──
    let vaa_bytes = fetch_signed_vaa(
        &client,
        &args.guardian_rpc,
        args.emitter_chain,
        &emitter,
        args.sequence,
    )
    .await?;
    if !vaa_hash_matches(&vaa_bytes, &msig.vaa_hash)? {
        bail!(
            "VAA/manager join failed: manager vaaHash {} != signed-VAA digest {}",
            hex::encode(msig.vaa_hash),
            hex::encode(vaa_signing_digest(&vaa_bytes)?),
        );
    }

    // ── 2. Parse VAA -> UTX0 payload ──
    let header = parse_vaa(&vaa_bytes)?;
    if header.emitter_chain != args.emitter_chain || header.emitter_address != emitter {
        bail!(
            "VAA emitter mismatch: got chain={} addr={} expected chain={} addr={}",
            header.emitter_chain,
            hex::encode(header.emitter_address),
            args.emitter_chain,
            hex::encode(emitter)
        );
    }
    if header.sequence != args.sequence {
        bail!(
            "VAA sequence mismatch: got {} expected {}",
            header.sequence,
            args.sequence
        );
    }
    let payload = Utx0UnlockPayload::parse(&header.payload)
        .context("VAA payload is not a valid UTX0 unlock payload")?;
    if payload.destination_chain != doge_local_ops::wormhole::chain_id::DOGECOIN {
        bail!(
            "UTX0 destination chain {} is not Dogecoin ({})",
            payload.destination_chain,
            doge_local_ops::wormhole::chain_id::DOGECOIN,
        );
    }
    if payload.delegated_manager_set_index != args.manager_set_index {
        bail!(
            "UTX0 manager set {} does not match requested set {}",
            payload.delegated_manager_set_index,
            args.manager_set_index,
        );
    }

    println!(
        "UTX0 payload: dest_chain={} manager_set={} inputs={} outputs={}",
        payload.destination_chain,
        payload.delegated_manager_set_index,
        payload.inputs.len(),
        payload.outputs.len()
    );
    validate_manager_metadata(
        &msig,
        args.emitter_chain,
        &emitter,
        args.sequence,
        args.manager_set_index,
        payload.destination_chain,
        &manager_set,
    )?;

    // ── 3. Rebuild per-input redeem scripts ──
    let redeem_scripts: Vec<Vec<u8>> = payload
        .inputs
        .iter()
        .map(|input| {
            build_redeem_script(
                header.emitter_chain,
                &header.emitter_address,
                &input.original_recipient_address,
                manager_set.m,
                &manager_set.pubkeys,
            )
        })
        .collect::<Result<_>>()?;

    // ── 4. Build unsigned tx + sighashes ──
    let mut tx = UnsignedTransaction::from_utx0(&payload, redeem_scripts.clone())?;
    let sighashes: Vec<[u8; 32]> = (0..tx.input_count())
        .map(|i| tx.sighash_all(i))
        .collect::<Result<_>>()?;

    // ── 5. Verify unique signatures + collect M valid sigs per input in pubkey order ──
    let per_input_sigs = collect_manager_signatures(
        &msig,
        &manager_set,
        &sighashes,
        args.manager_signing_enabled || args.broadcast_enabled,
    )?;

    // ── 6. Assemble scriptSig for each input (only when quorum is available) ──
    if let Some(per_input_sigs) = per_input_sigs {
        for (input_index, signatures) in per_input_sigs.iter().enumerate() {
            tx.apply_script_sig(input_index, signatures)?;
        }
    }

    // ── 7. Serialize + (dry-run: print only) broadcast via electrs POST /tx ──
    let raw_tx = tx.serialize();
    let txid = tx.txid();
    let raw_hex = hex::encode(&raw_tx);
    println!("unsigned->signed tx ({} bytes): {}", raw_tx.len(), raw_hex);
    println!("local txid: {}", hex::encode(txid));

    if args.broadcast_enabled {
        let broadcast_txid = broadcast_electrs(&client, &args.electrs_url, &raw_hex).await?;
        println!("broadcast OK, electrs txid: {broadcast_txid}");
    } else {
        println!("[dry-run] broadcast skipped (broadcast_enabled=false)");
        println!("[dry-run] signed tx hex: {raw_hex}");
    }
    Ok(())
}

fn validate_manager_metadata(
    signatures: &ManagerSignatures,
    emitter_chain: u16,
    emitter: &[u8; 32],
    sequence: u64,
    manager_set_index: u32,
    destination_chain: u16,
    manager_set: &ManagerSet,
) -> Result<()> {
    let expected_vaa_id = format!("{emitter_chain}/{}/{sequence}", hex::encode(emitter));
    if signatures.vaa_id != expected_vaa_id
        || signatures.destination_chain != destination_chain
        || signatures.manager_set_index != manager_set_index
        || signatures.required != manager_set.m as u32
        || signatures.total != manager_set.n as u32
    {
        bail!(
            "manager response metadata mismatch: vaa_id={:?} destination={} set={} quorum={}/{}; expected vaa_id={expected_vaa_id:?} destination={destination_chain} set={manager_set_index} quorum={}/{}",
            signatures.vaa_id,
            signatures.destination_chain,
            signatures.manager_set_index,
            signatures.required,
            signatures.total,
            manager_set.m,
            manager_set.n,
        );
    }
    Ok(())
}

fn collect_manager_signatures(
    signatures: &ManagerSignatures,
    manager_set: &ManagerSet,
    sighashes: &[[u8; 32]],
    require_quorum: bool,
) -> Result<Option<Vec<Vec<Vec<u8>>>>> {
    let mut seen_signers = HashSet::with_capacity(signatures.signatures.len());
    let mut per_input = vec![Vec::<(u8, Vec<u8>)>::new(); sighashes.len()];
    for signer in &signatures.signatures {
        if !seen_signers.insert(signer.signer_index) {
            bail!(
                "manager response contains duplicate signer {}",
                signer.signer_index
            );
        }
        let signer_index = signer.signer_index as usize;
        let public_key = manager_set.pubkeys.get(signer_index).ok_or_else(|| {
            anyhow!(
                "signer index {signer_index} out of range for manager set n={}",
                manager_set.n
            )
        })?;
        if signer.input_signatures.len() != sighashes.len() {
            bail!(
                "signer {signer_index} returned {} signatures, expected {}",
                signer.input_signatures.len(),
                sighashes.len(),
            );
        }
        for (input_index, signature) in signer.input_signatures.iter().enumerate() {
            if !verify_manager_signature(public_key, &sighashes[input_index], signature)? {
                bail!("signature verification failed: signer {signer_index} input {input_index}");
            }
            per_input[input_index].push((signer.signer_index, signature.clone()));
        }
    }

    let mut have_quorum = true;
    let mut selected_per_input = Vec::with_capacity(per_input.len());
    for (input_index, candidates) in per_input.iter_mut().enumerate() {
        candidates.sort_by_key(|(signer_index, _)| *signer_index);
        if candidates.len() < manager_set.m as usize {
            have_quorum = false;
            if require_quorum {
                bail!(
                    "input {input_index} has only {} unique valid signatures, need m={}",
                    candidates.len(),
                    manager_set.m,
                );
            }
            println!(
                "[dry-run] input {input_index} has {}/{} unique valid manager signatures; scriptSig assembly skipped",
                candidates.len(),
                manager_set.m,
            );
        }
        selected_per_input.push(
            candidates
                .iter()
                .take(manager_set.m as usize)
                .map(|(_, signature)| signature.clone())
                .collect(),
        );
    }
    Ok(have_quorum.then_some(selected_per_input))
}

/// Resolve a manager set by index. Index 0 is the deterministic local-regtest
/// fixture; public-network manager sets must be fetched from their source of truth.
fn resolve_manager_set(index: u32) -> Result<ManagerSet> {
    if index == 0 {
        return Ok(local_regtest_manager_set());
    }
    bail!("manager set index {index} is unavailable; use index 0 only for isolated local regtest")
}

async fn wait_for_signatures(
    client: &reqwest::Client,
    base_url: &str,
    emitter_chain: u16,
    emitter: &[u8; 32],
    sequence: u64,
    poll_interval: u64,
    timeout_secs: u64,
) -> Result<doge_local_ops::wormhole::manager::ManagerSignatures> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut last = None;
    loop {
        let res =
            fetch_manager_signatures(client, base_url, emitter_chain, emitter, sequence).await;
        match res {
            Ok(ms) if ms.is_complete => return Ok(ms),
            Ok(ms) => {
                println!(
                    "waiting for signatures: complete=false, signers={}",
                    ms.signatures.len()
                );
                last = None;
            }
            Err(e) => {
                // Keep the last error but keep polling until the deadline.
                last = Some(e.to_string());
            }
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out after {timeout_secs}s waiting for manager signatures: {}",
                last.unwrap_or_else(|| "no response".into())
            );
        }
        sleep(Duration::from_secs(poll_interval)).await;
    }
}

/// Broadcast a raw transaction via electrs `POST /tx` (body = raw hex string).
async fn broadcast_electrs(
    client: &reqwest::Client,
    electrs_base: &str,
    raw_hex: &str,
) -> Result<String> {
    let url = format!("{}/tx", electrs_base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(raw_hex.to_owned())
        .send()
        .await
        .map_err(|e| anyhow!("electrs POST /tx failed: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.context("electrs: read body")?;
    if !status.is_success() {
        bail!("electrs broadcast returned {status}: {text}");
    }
    // electrs returns the txid as a plain hex string (with surrounding quotes
    // for JSON content type); strip quotes/whitespace.
    Ok(text.trim().trim_matches('"').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use doge_local_ops::wormhole::{
        manager::{build_local_signed_withdrawal, LocalWithdrawalRegistration, VaaKey},
        redeem::build_redeem_script,
        utx0::{Utx0Input, Utx0Output, UtxoAddressType},
    };

    fn fixture() -> (ManagerSet, ManagerSignatures, Vec<[u8; 32]>, [u8; 32]) {
        let emitter = [0x42; 32];
        let payload = Utx0UnlockPayload {
            destination_chain: doge_local_ops::wormhole::chain_id::DOGECOIN,
            delegated_manager_set_index: 0,
            inputs: vec![Utx0Input {
                original_recipient_address: [0x11; 32],
                transaction_id: [0x22; 32],
                vout: 0,
            }],
            outputs: vec![Utx0Output {
                amount: 100_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: vec![0x55; 20],
            }],
        };
        let registration = LocalWithdrawalRegistration {
            key: VaaKey {
                emitter_chain: 1,
                emitter_address: emitter,
                sequence: 9,
            },
            payload: payload.serialize().unwrap(),
        };
        let signed = build_local_signed_withdrawal(&registration).unwrap();
        let manager_set = local_regtest_manager_set();
        let redeem_scripts = payload
            .inputs
            .iter()
            .map(|input| {
                build_redeem_script(
                    1,
                    &emitter,
                    &input.original_recipient_address,
                    manager_set.m,
                    &manager_set.pubkeys,
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let tx = UnsignedTransaction::from_utx0(&payload, redeem_scripts).unwrap();
        let sighashes = (0..tx.input_count())
            .map(|input_index| tx.sighash_all(input_index))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        (manager_set, signed.manager_signatures, sighashes, emitter)
    }

    #[test]
    fn rejects_duplicate_manager_signer_and_wrong_sighash_type() {
        let (manager_set, mut signatures, sighashes, _) = fixture();
        signatures.signatures[1].signer_index = signatures.signatures[0].signer_index;
        assert!(
            collect_manager_signatures(&signatures, &manager_set, &sighashes, true)
                .unwrap_err()
                .to_string()
                .contains("duplicate signer")
        );

        let (_, mut signatures, sighashes, _) = fixture();
        *signatures.signatures[0].input_signatures[0]
            .last_mut()
            .unwrap() = 2;
        assert!(
            collect_manager_signatures(&signatures, &manager_set, &sighashes, true)
                .unwrap_err()
                .to_string()
                .contains("not SIGHASH_ALL")
        );
    }

    #[test]
    fn validates_metadata_and_sorts_unique_quorum_by_pubkey_index() {
        let (manager_set, mut signatures, sighashes, emitter) = fixture();
        validate_manager_metadata(
            &signatures,
            1,
            &emitter,
            9,
            0,
            doge_local_ops::wormhole::chain_id::DOGECOIN,
            &manager_set,
        )
        .unwrap();
        signatures.signatures.reverse();
        let selected = collect_manager_signatures(&signatures, &manager_set, &sighashes, true)
            .unwrap()
            .expect("5-of-7 quorum");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].len(), manager_set.m as usize);

        signatures.required = 4;
        assert!(validate_manager_metadata(
            &signatures,
            1,
            &emitter,
            9,
            0,
            doge_local_ops::wormhole::chain_id::DOGECOIN,
            &manager_set,
        )
        .is_err());
    }
}
