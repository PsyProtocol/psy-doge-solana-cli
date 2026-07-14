pub mod custody_ops;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use sha2::Digest;
use std::{fs, path::Path};

pub const SATS_PER_DOGE: u64 = 100_000_000;
pub const GROTH16_PROOF_SIZE: usize = 356;
pub const BLOCK_PUBLIC_VALUES_SIZE: usize = 32;

/// Parse a Dogecoin Core JSON amount without passing through binary floating point.
///
/// Dogecoin Core represents transaction output values as JSON numbers in DOGE. This
/// parser accepts at most eight fractional digits and returns exact koinu/satoshis.
pub fn doge_amount_to_sats(value: &Value) -> Result<u64> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        other => bail!("Dogecoin amount must be a number or decimal string, got {other}"),
    };
    parse_doge_decimal(&text)
}

fn parse_doge_decimal(text: &str) -> Result<u64> {
    let normalized = text.trim();
    if normalized.is_empty() {
        bail!("Dogecoin amount is empty");
    }
    if normalized.starts_with('-') {
        bail!("Dogecoin amount cannot be negative: {normalized}");
    }
    if let Some(exponent_index) = normalized.find(['e', 'E']) {
        return parse_scientific_doge_decimal(normalized, exponent_index);
    }
    if normalized.starts_with('+') {
        bail!("Dogecoin amount must use unsigned decimal notation: {normalized}");
    }

    let mut parts = normalized.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some() || whole.is_empty() {
        bail!("invalid Dogecoin decimal amount: {normalized}");
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("invalid Dogecoin decimal amount: {normalized}");
    }
    if fraction.len() > 8 {
        bail!("Dogecoin amount has more than eight fractional digits: {normalized}");
    }

    let whole_sats = whole
        .parse::<u64>()
        .with_context(|| format!("invalid whole-DOGE amount: {whole}"))?
        .checked_mul(SATS_PER_DOGE)
        .ok_or_else(|| anyhow!("Dogecoin amount overflows u64 satoshis: {normalized}"))?;
    let fraction_sats = if fraction.is_empty() {
        0
    } else {
        let digits = fraction
            .parse::<u64>()
            .with_context(|| format!("invalid fractional DOGE amount: {fraction}"))?;
        digits
            .checked_mul(10u64.pow((8 - fraction.len()) as u32))
            .ok_or_else(|| anyhow!("Dogecoin fractional amount overflows: {normalized}"))?
    };
    whole_sats
        .checked_add(fraction_sats)
        .ok_or_else(|| anyhow!("Dogecoin amount overflows u64 satoshis: {normalized}"))
}

fn parse_scientific_doge_decimal(text: &str, exponent_index: usize) -> Result<u64> {
    let (mantissa, exponent_with_marker) = text.split_at(exponent_index);
    let exponent = exponent_with_marker[1..]
        .parse::<i32>()
        .with_context(|| format!("invalid Dogecoin amount exponent: {text}"))?;
    let mut digits = String::with_capacity(mantissa.len());
    let mut fractional_digits = 0i32;
    let mut saw_dot = false;
    for byte in mantissa.bytes() {
        match byte {
            b'.' if !saw_dot => saw_dot = true,
            b'0'..=b'9' => {
                digits.push(byte as char);
                if saw_dot {
                    fractional_digits += 1;
                }
            }
            _ => bail!("invalid Dogecoin scientific amount: {text}"),
        }
    }
    if digits.is_empty() {
        bail!("invalid Dogecoin scientific amount: {text}");
    }
    let satoshi_shift = exponent - fractional_digits + 8;
    if satoshi_shift < 0 {
        bail!("Dogecoin amount has sub-satoshi precision: {text}");
    }
    let base = digits
        .parse::<u64>()
        .with_context(|| format!("invalid Dogecoin scientific amount: {text}"))?;
    base.checked_mul(
        10u64
            .checked_pow(satoshi_shift as u32)
            .ok_or_else(|| anyhow!("Dogecoin amount exponent overflows: {text}"))?,
    )
    .ok_or_else(|| anyhow!("Dogecoin amount overflows u64 satoshis: {text}"))
}

/// Locate exactly one output paying `address`, returning its vout and exact amount.
pub fn extract_vout_and_sats(verbose: &Value, address: &str) -> Result<(u32, u64)> {
    let vouts = verbose
        .get("vout")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("verbose transaction missing vout array"))?;
    let mut match_found = None;

    for vout in vouts {
        let script = vout.get("scriptPubKey").unwrap_or(&Value::Null);
        let direct_match = script.get("address").and_then(Value::as_str) == Some(address);
        let list_match = script
            .get("addresses")
            .and_then(Value::as_array)
            .map(|values| values.iter().any(|value| value.as_str() == Some(address)))
            .unwrap_or(false);
        if !direct_match && !list_match {
            continue;
        }

        let index_u64 = vout
            .get("n")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("matching vout missing nonnegative index"))?;
        let index = u32::try_from(index_u64).context("matching vout index exceeds u32")?;
        let sats = doge_amount_to_sats(
            vout.get("value")
                .ok_or_else(|| anyhow!("matching vout missing value"))?,
        )?;
        if match_found.replace((index, sats)).is_some() {
            bail!("transaction has multiple outputs for address {address}; exact vout is ambiguous");
        }
    }

    match_found.ok_or_else(|| anyhow!("transaction has no output for address {address}"))
}

pub fn validate_proof_artifacts(
    proof_path: &Path,
    public_values_path: &Path,
) -> Result<([u8; GROTH16_PROOF_SIZE], [u8; BLOCK_PUBLIC_VALUES_SIZE])> {
    let proof = fs::read(proof_path)
        .with_context(|| format!("read proof artifact {}", proof_path.display()))?;
    let public_values = fs::read(public_values_path).with_context(|| {
        format!(
            "read public-values artifact {}",
            public_values_path.display()
        )
    })?;
    validate_proof_artifact_bytes(&proof, &public_values)
}

pub fn validate_proof_artifact_bytes(
    proof: &[u8],
    public_values: &[u8],
) -> Result<([u8; GROTH16_PROOF_SIZE], [u8; BLOCK_PUBLIC_VALUES_SIZE])> {
    let proof: [u8; GROTH16_PROOF_SIZE] = proof.try_into().map_err(|_| {
        anyhow!(
            "SP1 Groth16 proof must be exactly {GROTH16_PROOF_SIZE} bytes, got {}",
            proof.len()
        )
    })?;
    let public_values: [u8; BLOCK_PUBLIC_VALUES_SIZE] = public_values.try_into().map_err(|_| {
        anyhow!(
            "block-transition public values must be exactly {BLOCK_PUBLIC_VALUES_SIZE} bytes, got {}",
            public_values.len()
        )
    })?;
    Ok((proof, public_values))
}


/// Explicit output plan for a tracked-custody withdrawal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyTransactionPlan {
    pub recipient_sats: u64,
    pub change_sats: u64,
    pub fee_sats: u64,
}

/// Canonical identity used by the local tracked-UTXO spent commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackedSpentOutpoint {
    pub txid: [u8; 32],
    pub vout: u32,
    pub leaf_index: u64,
}

/// Plan recipient, change, and an explicit fee without silently donating custody value.
pub fn plan_custody_transaction(
    selected_sats: u64,
    recipient_sats: u64,
    fee_sats: u64,
    dust_threshold_sats: u64,
) -> Result<CustodyTransactionPlan> {
    if recipient_sats == 0 {
        bail!("custody transaction recipient amount must be greater than zero");
    }
    let required = recipient_sats
        .checked_add(fee_sats)
        .ok_or_else(|| anyhow!("recipient plus fee overflows u64"))?;
    let change_sats = selected_sats.checked_sub(required).ok_or_else(|| {
        anyhow!(
            "insufficient tracked custody funds: selected {selected_sats} sats, need {required} sats"
        )
    })?;
    if change_sats != 0 && change_sats < dust_threshold_sats {
        bail!(
            "tracked custody change {change_sats} sats is below explicit dust threshold {dust_threshold_sats}; select different inputs or fee rather than donating it"
        );
    }
    Ok(CustodyTransactionPlan {
        recipient_sats,
        change_sats,
        fee_sats,
    })
}

/// Validate a decoded Dogecoin transaction against the exact selected inputs and output plan.
///
/// This deliberately validates values as exact satoshis and rejects extra wallet-selected inputs
/// or outputs. `decoderawtransaction` output from both unsigned and signed forms is accepted.
pub fn validate_decoded_custody_transaction(
    decoded: &Value,
    expected_inputs: &[(String, u32)],
    recipient_address: &str,
    change_address: Option<&str>,
    plan: &CustodyTransactionPlan,
    selected_sats: u64,
) -> Result<()> {
    let vins = decoded
        .get("vin")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("decoded transaction missing vin array"))?;
    if vins.len() != expected_inputs.len() {
        bail!(
            "decoded transaction has {} inputs, expected exactly {} tracked inputs",
            vins.len(),
            expected_inputs.len()
        );
    }
    let mut actual_inputs = vins
        .iter()
        .map(|vin| {
            let txid = vin
                .get("txid")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("decoded input missing txid"))?
                .to_ascii_lowercase();
            let vout = vin
                .get("vout")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("decoded input missing vout"))?;
            Ok((txid, u32::try_from(vout).context("decoded input vout exceeds u32")?))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut wanted_inputs = expected_inputs
        .iter()
        .map(|(txid, vout)| (txid.to_ascii_lowercase(), *vout))
        .collect::<Vec<_>>();
    actual_inputs.sort_unstable();
    wanted_inputs.sort_unstable();
    if actual_inputs != wanted_inputs {
        bail!("decoded transaction inputs differ from the atomically reserved custody outpoints");
    }

    let vouts = decoded
        .get("vout")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("decoded transaction missing vout array"))?;
    let expected_output_count = 1 + usize::from(plan.change_sats != 0);
    if vouts.len() != expected_output_count {
        bail!(
            "decoded transaction has {} outputs, expected exactly {expected_output_count}",
            vouts.len()
        );
    }
    if plan.change_sats != 0 && change_address == Some(recipient_address) {
        bail!("custody change address must differ from the withdrawal recipient");
    }
    let mut recipient_matches = 0usize;
    let mut change_matches = 0usize;
    let mut total_output_sats = 0u64;
    for output in vouts {
        let amount = doge_amount_to_sats(
            output
                .get("value")
                .ok_or_else(|| anyhow!("decoded output missing value"))?,
        )?;
        total_output_sats = total_output_sats
            .checked_add(amount)
            .ok_or_else(|| anyhow!("decoded output total overflows u64"))?;
        let script = output.get("scriptPubKey").unwrap_or(&Value::Null);
        let matches_address = |address: &str| {
            script.get("address").and_then(Value::as_str) == Some(address)
                || script
                    .get("addresses")
                    .and_then(Value::as_array)
                    .map(|addresses| addresses.iter().any(|candidate| candidate.as_str() == Some(address)))
                    .unwrap_or(false)
        };
        if matches_address(recipient_address) && amount == plan.recipient_sats {
            recipient_matches += 1;
        }
        if let Some(address) = change_address {
            if matches_address(address) && amount == plan.change_sats {
                change_matches += 1;
            }
        }
    }
    if recipient_matches != 1 {
        bail!("decoded transaction does not contain exactly one authoritative recipient output");
    }
    if plan.change_sats != 0 && change_matches != 1 {
        bail!("decoded transaction does not contain exactly one explicit custody change output");
    }
    let actual_fee = selected_sats
        .checked_sub(total_output_sats)
        .ok_or_else(|| anyhow!("decoded outputs exceed selected custody inputs"))?;
    if actual_fee != plan.fee_sats {
        bail!(
            "decoded transaction fee is {actual_fee} sats, expected explicit {} sats",
            plan.fee_sats
        );
    }
    Ok(())
}

/// Compute the narrow local tracked-UTXO spent commitment used by these operator utilities.
///
/// The current withdrawal guest has no authoritative Dogecoin spent-root witness algorithm. To
/// avoid inventing production semantics, this commitment is explicitly domain-separated and rolls
/// the prior on-chain root together with the deterministically ordered local custody outpoints:
/// `SHA256(domain || old_root || count_le || (leaf_index_le || txid_internal || vout_le)...)`.
pub fn tracked_utxo_spent_commitment(
    old_root: [u8; 32],
    outpoints: &[TrackedSpentOutpoint],
) -> Result<[u8; 32]> {
    if outpoints.is_empty() {
        bail!("cannot update tracked-UTXO spent commitment with no spent outpoints");
    }
    let mut ordered = outpoints.to_vec();
    ordered.sort_unstable_by_key(|outpoint| (outpoint.leaf_index, outpoint.txid, outpoint.vout));
    for pair in ordered.windows(2) {
        if pair[0].leaf_index == pair[1].leaf_index {
            bail!("duplicate tracked custody leaf index {}", pair[0].leaf_index);
        }
    }
    const DOMAIN: &[u8] = b"psy-doge-local-tracked-spent-v1";
    let mut preimage = Vec::with_capacity(DOMAIN.len() + 32 + 8 + ordered.len() * 44);
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(&old_root);
    preimage.extend_from_slice(&(ordered.len() as u64).to_le_bytes());
    for outpoint in ordered {
        preimage.extend_from_slice(&outpoint.leaf_index.to_le_bytes());
        preimage.extend_from_slice(&outpoint.txid);
        preimage.extend_from_slice(&outpoint.vout.to_le_bytes());
    }
    Ok(sha2::Sha256::digest(preimage).into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_dogecoin_amounts_exactly() {
        assert_eq!(doge_amount_to_sats(&json!(1)).unwrap(), 100_000_000);
        assert_eq!(doge_amount_to_sats(&json!(0.00000001)).unwrap(), 1);
        assert_eq!(doge_amount_to_sats(&json!("12.34000000")).unwrap(), 1_234_000_000);
        assert!(doge_amount_to_sats(&json!("1.000000001")).is_err());
        assert!(doge_amount_to_sats(&json!(-1)).is_err());
    }

    #[test]
    fn finds_legacy_and_modern_address_fields() {
        let legacy = json!({
            "vout": [
                {"n": 0, "value": 3.0, "scriptPubKey": {"addresses": ["change"]}},
                {"n": 2, "value": 1.25, "scriptPubKey": {"addresses": ["deposit"]}}
            ]
        });
        assert_eq!(extract_vout_and_sats(&legacy, "deposit").unwrap(), (2, 125_000_000));

        let modern = json!({
            "vout": [{"n": 7, "value": "0.00000001", "scriptPubKey": {"address": "deposit"}}]
        });
        assert_eq!(extract_vout_and_sats(&modern, "deposit").unwrap(), (7, 1));
    }

    #[test]
    fn rejects_missing_or_ambiguous_outputs() {
        let tx = json!({
            "vout": [
                {"n": 0, "value": 1, "scriptPubKey": {"addresses": ["same"]}},
                {"n": 1, "value": 2, "scriptPubKey": {"addresses": ["same"]}}
            ]
        });
        assert!(extract_vout_and_sats(&tx, "missing").is_err());
        assert!(extract_vout_and_sats(&tx, "same").is_err());
    }

    #[test]
    fn validates_exact_proof_artifact_lengths() {
        let proof = vec![7u8; GROTH16_PROOF_SIZE];
        let public_values = vec![9u8; BLOCK_PUBLIC_VALUES_SIZE];
        let (proof_array, values_array) =
            validate_proof_artifact_bytes(&proof, &public_values).unwrap();
        assert_eq!(proof_array[0], 7);
        assert_eq!(values_array[0], 9);
        assert!(validate_proof_artifact_bytes(&proof[..355], &public_values).is_err());
        assert!(validate_proof_artifact_bytes(&proof, &public_values[..31]).is_err());
    }

    #[test]
    fn plans_custody_transaction_exactly() {
        let plan = plan_custody_transaction(100_000, 70_000, 10_000, 3_000).unwrap();
        assert_eq!(plan.recipient_sats, 70_000);
        assert_eq!(plan.change_sats, 20_000);
        assert_eq!(plan.fee_sats, 10_000);
    }

    #[test]
    fn plan_rejects_insufficient_funds() {
        assert!(plan_custody_transaction(50_000, 70_000, 10_000, 3_000).is_err());
    }
    #[test]
    fn plan_rejects_dust_change() {
        // Zero change (exact match) is always valid
        assert!(plan_custody_transaction(73_000, 70_000, 3_000, 3_000).is_ok());
        // Non-zero change below dust is rejected
        assert!(plan_custody_transaction(74_000, 70_000, 3_000, 3_000).is_err());
        // Exactly at dust threshold is OK
        assert!(plan_custody_transaction(76_000, 70_000, 3_000, 3_000).is_ok());
    }

    #[test]
    fn plan_zero_change_is_valid() {
        let plan = plan_custody_transaction(80_000, 70_000, 10_000, 3_000).unwrap();
        assert_eq!(plan.change_sats, 0);
    }

    #[test]
    fn validates_custody_transaction_inputs_and_outputs() {
        let inputs = vec![
            ("abc123".to_owned(), 0u32),
            ("def456".to_owned(), 1u32),
        ];
        let decoded = json!({
            "vin": [
                {"txid": "abc123", "vout": 0},
                {"txid": "def456", "vout": 1}
            ],
            "vout": [
                {"n": 0, "value": 0.7, "scriptPubKey": {"address": "recipient"}},
                {"n": 1, "value": 0.1, "scriptPubKey": {"address": "change-addr"}}
            ]
        });
        let plan = CustodyTransactionPlan { recipient_sats: 70_000_000, change_sats: 10_000_000, fee_sats: 20_000_000 };
        validate_decoded_custody_transaction(&decoded, &inputs, "recipient", Some("change-addr"), &plan, 100_000_000).unwrap();
    }

    #[test]
    fn validation_rejects_extra_inputs() {
        let decoded = json!({
            "vin": [
                {"txid": "abc", "vout": 0},
                {"txid": "extra", "vout": 0}
            ],
            "vout": [{"n": 0, "value": 0.5, "scriptPubKey": {"address": "r"}}]
        });
        let plan = CustodyTransactionPlan { recipient_sats: 50_000_000, change_sats: 0, fee_sats: 10_000_000 };
        let err = validate_decoded_custody_transaction(
            &decoded, &[("abc".to_owned(), 0u32)], "r", None, &plan, 60_000_000,
        ).unwrap_err();
        assert!(err.to_string().contains("2 inputs, expected exactly 1"));
    }

    #[test]
    fn tracked_commitment_rejects_empty_outpoints() {
        assert!(tracked_utxo_spent_commitment([0u8; 32], &[]).is_err());
    }

    #[test]
    fn tracked_commitment_is_deterministic() {
        let outpoints = vec![
            TrackedSpentOutpoint { txid: [1u8; 32], vout: 0, leaf_index: 5 },
            TrackedSpentOutpoint { txid: [2u8; 32], vout: 1, leaf_index: 3 },
        ];
        let h1 = tracked_utxo_spent_commitment([0u8; 32], &outpoints).unwrap();
        let h2 = tracked_utxo_spent_commitment([0u8; 32], &outpoints).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn tracked_commitment_sorts_outpoints() {
        let outpoints = vec![
            TrackedSpentOutpoint { txid: [1u8; 32], vout: 0, leaf_index: 10 },
            TrackedSpentOutpoint { txid: [2u8; 32], vout: 1, leaf_index: 5 },
        ];
        let h1 = tracked_utxo_spent_commitment([0u8; 32], &outpoints).unwrap();
        let mut reversed = vec![
            TrackedSpentOutpoint { txid: [2u8; 32], vout: 1, leaf_index: 5 },
            TrackedSpentOutpoint { txid: [1u8; 32], vout: 0, leaf_index: 10 },
        ];
        let h2 = tracked_utxo_spent_commitment([0u8; 32], &reversed).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn tracked_commitment_rejects_duplicate_leaf() {
        let outpoints = vec![
            TrackedSpentOutpoint { txid: [1u8; 32], vout: 0, leaf_index: 5 },
            TrackedSpentOutpoint { txid: [2u8; 32], vout: 1, leaf_index: 5 },
        ];
        assert!(tracked_utxo_spent_commitment([0u8; 32], &outpoints).is_err());
    }
}
