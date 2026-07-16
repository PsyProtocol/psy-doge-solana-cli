//! P2SH redeem-script builder for the Dogecoin Wormhole bridge.
//!
//! Byte-identical to `wormhole/node/pkg/manager/dogecoin/script.go`
//! (`BuildRedeemScript`). The script mirrors the Wormhole whitepaper:
//!
//! ```text
//! <emitter_chain u16 BE>      // minimal data push (0x02 || 2 bytes)
//! <emitter_contract 32B>      // 0x20 || 32 bytes
//! OP_2DROP                     // 0x6b
//! <recipient 32B>             // 0x20 || 32 bytes
//! OP_DROP                      // 0x75
//! OP_M                         // 0x51 + (m-1)   (m in 1..=16)
//! <pubkey_1 33B> ... <pubkey_n 33B>   // 0x21 || 33 bytes each
//! OP_N                         // 0x51 + (n-1)
//! OP_CHECKMULTISIG             // 0xae
//! ```
//!
//! `btcd`'s `ScriptBuilder.AddData` emits a minimal push for the data
//! payload (length-prefix `0x01..=0x4b` for sizes ≤75), and `AddInt64`
//! emits `OP_1..OP_16` for integers `1..=16`. We reproduce both exactly.

use anyhow::{bail, Result};

// Minimal-push / data opcodes (matching btcd txscript).
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;

// Stack opcodes used by the redeem script.
const OP_0: u8 = 0x00;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51; // OP_n = OP_1 + (n - 1) for n in 1..=16
const OP_2DROP: u8 = 0x6b;
const OP_DROP: u8 = 0x75;
const OP_CHECKMULTISIG: u8 = 0xae;

/// Maximum pubkeys accepted by this redeem-script shape (matches the Go
/// helper's `> 13` guard).
const MAX_PUBKEYS: usize = 13;
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Push `data` as a minimal data push, identical to btcd's `AddData`.
fn push_data(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 0x4b {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(OP_PUSHDATA1);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(OP_PUSHDATA2);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        buf.push(OP_PUSHDATA4);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    }
    buf.extend_from_slice(data);
}

/// Push a small integer using `OP_1NEGATE` / `OP_0` / `OP_1..OP_16`, else a
/// minimal little-endian data push — identical to btcd's `AddInt64`.
fn push_int(buf: &mut Vec<u8>, val: i64) {
    if val == 0 {
        buf.push(OP_0);
        return;
    }
    if val == -1 {
        buf.push(OP_1NEGATE);
        return;
    }
    if val >= 1 && val <= 16 {
        buf.push(OP_1 + (val as u8) - 1);
        return;
    }
    // Minimal little-endian encoding for larger magnitudes (not reached for
    // the m/n values this builder is used with, kept for fidelity).
    let mut neg = false;
    let mut v = val;
    if v < 0 {
        neg = true;
        v = -v;
    }
    let mut bytes = Vec::new();
    let mut tmp = v as u128;
    while tmp != 0 {
        bytes.push((tmp & 0xff) as u8);
        tmp >>= 8;
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    // Strip trailing (high) zero bytes unless the sign bit would be ambiguous.
    while bytes.len() > 1 && *bytes.last().unwrap() == 0x00 {
        bytes.pop();
    }
    if (*bytes.last().unwrap() & 0x80) != 0 {
        // Need a sign byte.
        bytes.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *bytes.last_mut().unwrap() |= 0x80;
    }
    push_data(buf, &bytes);
}

/// Build the Wormhole Dogecoin P2SH redeem script.
///
/// Arguments mirror `BuildRedeemScript` in `script.go`:
///   * `emitter_chain`   — Wormhole chain ID of the emitter (u16, big-endian
///     in the script).
///   * `emitter_contract` — 32-byte emitter address.
///   * `recipient`       — 32-byte original recipient address embedded in the
///     deposit's lock script.
///   * `m`               — multisig threshold.
///   * `pubkeys`         — `n` compressed secp256k1 public keys (33 bytes
///     each).
///
/// Returns the serialized redeem script. Errors mirror the Go helper
/// (`too many pubkeys`, `invalid m-of-n`, invalid pubkey length).
pub fn build_redeem_script(
    emitter_chain: u16,
    emitter_contract: &[u8; 32],
    recipient: &[u8; 32],
    m: u8,
    pubkeys: &[[u8; COMPRESSED_PUBKEY_LEN]],
) -> Result<Vec<u8>> {
    if pubkeys.len() > MAX_PUBKEYS {
        bail!(
            "too many pubkeys: {} (max {MAX_PUBKEYS} for this redeem script)",
            pubkeys.len()
        );
    }
    let n = pubkeys.len() as u8;
    if m < 1 || m > n {
        bail!("invalid m-of-n: m={m}, n={n}");
    }
    for (i, pk) in pubkeys.iter().enumerate() {
        if pk.len() != COMPRESSED_PUBKEY_LEN {
            bail!(
                "pubkey {i} has invalid length {} (expected {COMPRESSED_PUBKEY_LEN} for compressed)",
                pk.len()
            );
        }
    }

    let mut buf = Vec::with_capacity(3 + 33 + 1 + 33 + 1 + 1 + pubkeys.len() * 34 + 1 + 1);

    // emitter_chain (2 bytes, big-endian) as a minimal data push.
    let chain_bytes = emitter_chain.to_be_bytes();
    push_data(&mut buf, &chain_bytes);
    // emitter_contract (32 bytes).
    push_data(&mut buf, emitter_contract);
    // OP_2DROP drops the chain + contract pair.
    buf.push(OP_2DROP);
    // recipient (32 bytes).
    push_data(&mut buf, recipient);
    // OP_DROP drops the recipient.
    buf.push(OP_DROP);
    // OP_M (threshold).
    push_int(&mut buf, m as i64);
    // pubkeys.
    for pk in pubkeys {
        push_data(&mut buf, pk);
    }
    // OP_N (total pubkeys).
    push_int(&mut buf, n as i64);
    // OP_CHECKMULTISIG.
    buf.push(OP_CHECKMULTISIG);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(s: &str) -> [u8; 33] {
        let mut a = [0u8; 33];
        hex::decode_to_slice(s, &mut a).unwrap();
        a
    }

    fn a32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        hex::decode_to_slice(s, &mut a).unwrap();
        a
    }

    // Reproduces `TestBuildRedeemScript` from `script_test.go` byte-for-byte.
    #[test]
    fn matches_wormhole_script_go_basic() {
        let emitter_chain = 1u16; // ChainIDSolana
        let emitter_contract =
            a32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let recipient = a32("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        let pubkeys = vec![
            pk("02a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575"),
            pk("036ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640d"),
        ];

        let script =
            build_redeem_script(emitter_chain, &emitter_contract, &recipient, 2, &pubkeys).unwrap();

        // Hand-derived expectation matching btcd AddData/AddInt64:
        //   0x02 0x00 0x01            (push 2-byte chain BE = 1)
        //   0x20 <contract>           (push 32-byte contract)
        //   0x6b                      (OP_2DROP)
        //   0x20 <recipient>          (push 32-byte recipient)
        //   0x75                      (OP_DROP)
        //   0x52                      (OP_2 = m)
        //   0x21 <pk1>                (push 33-byte pubkey)
        //   0x21 <pk2>
        //   0x52                      (OP_2 = n)
        //   0xae                      (OP_CHECKMULTISIG)
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x02, 0x00, 0x01]);
        expected.push(0x20);
        expected.extend_from_slice(&emitter_contract);
        expected.push(0x6b);
        expected.push(0x20);
        expected.extend_from_slice(&recipient);
        expected.push(0x75);
        expected.push(0x52); // m = 2
        expected.push(0x21);
        expected.extend_from_slice(&pubkeys[0]);
        expected.push(0x21);
        expected.extend_from_slice(&pubkeys[1]);
        expected.push(0x52); // n = 2
        expected.push(0xae);

        assert_eq!(script, expected, "redeem script bytes must match script.go");
        assert!(script.len() <= 520);
    }

    // Reproduces the 5-of-7 shape from `TestBuildRedeemScriptMOfN`.
    #[test]
    fn matches_wormhole_script_go_5_of_7() {
        let mut pubkeys = Vec::with_capacity(7);
        for i in 0..7u8 {
            let mut pk = [0u8; 33];
            pk[0] = 0x02;
            pk[1] = i + 1;
            pubkeys.push(pk);
        }
        let contract = [0u8; 32];
        let recipient = [0u8; 32];
        let script = build_redeem_script(1u16, &contract, &recipient, 5, &pubkeys).unwrap();
        assert!(script.len() <= 520);
        // m = 5 -> OP_5 (0x55); n = 7 -> OP_7 (0x57).
        assert_eq!(script[script.len() - 1], 0xae); // OP_CHECKMULTISIG
        assert!(script.contains(&0x55));
        assert!(script.contains(&0x57));
        assert!(script.contains(&0x6b)); // OP_2DROP
        assert!(script.contains(&0x75)); // OP_DROP
    }

    #[test]
    fn rejects_invalid_m_of_n() {
        let pubkeys = vec![pk(
            "02a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575",
        )];
        let contract = [0u8; 32];
        let recipient = [0u8; 32];
        // m = 0
        assert!(build_redeem_script(1u16, &contract, &recipient, 0, &pubkeys).is_err());
        // m > n
        assert!(build_redeem_script(1u16, &contract, &recipient, 2, &pubkeys).is_err());
    }

    #[test]
    fn rejects_too_many_pubkeys() {
        let pubkeys = vec![
            [
                0x02u8, 0x01, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            ];
            14
        ];
        let contract = [0u8; 32];
        let recipient = [0u8; 32];
        assert!(build_redeem_script(1u16, &contract, &recipient, 10, &pubkeys).is_err());
    }

    #[test]
    fn is_deterministic() {
        let contract = a32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let recipient = a32("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        let pubkeys = vec![
            pk("02a882d414e478039cd5b52a92ffb13dd5e6bd4515497439dffd691a0f12af9575"),
            pk("036ce31db9bdd543e72fe3039a1f1c047dab87037c36a669ff90e28da1848f640d"),
        ];
        let a = build_redeem_script(1u16, &contract, &recipient, 2, &pubkeys).unwrap();
        let b = build_redeem_script(1u16, &contract, &recipient, 2, &pubkeys).unwrap();
        assert_eq!(a, b);
    }
}
