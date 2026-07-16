//! Legacy (pre-segwit) Dogecoin transaction builder, sighash, scriptSig and
//! broadcast serialization for the Wormhole UTXO relay.
//!
//! Mirrors `wormhole/node/pkg/manager/dogecoin/transaction.go`:
//!   * `BuildUnsignedTransaction`  -> [`UnsignedTransaction::from_utx0`]
//!   * `ComputeSighash`            -> [`UnsignedTransaction::sighash_all`]
//!   * `ApplySignatureToInput`     -> [`UnsignedTransaction::apply_script_sig`]
//!   * `SerializeForBroadcast`     -> [`UnsignedTransaction::serialize`]
//!   * `TxHash`                    -> [`UnsignedTransaction::txid`]
//!
//! Wire format (Bitcoin/Dogecoin consensus, little-endian):
//!   version(u32 LE) + varint(in_count) + tx_in[] + varint(out_count)
//!   + tx_out[] + locktime(u32 LE)
//! TxIn:  prev_txid(32 LE) + vout(u32 LE) + varint(script_len) + script
//!        + sequence(u32 LE)
//! TxOut: value(u64 LE) + varint(script_len) + script
//!
//! The transaction version is `1` (btcd `wire.TxVersion`) and the input
//! sequence is `0xffffffff`, matching the Go manager service.

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};

use super::utx0::{Utx0UnlockPayload, UtxoAddressType};

/// SIGHASH_ALL (0x01) — the only hash type used by the manager service.
pub const SIGHASH_ALL: u32 = 0x01;

/// Bitcoin wire transaction version used by the Wormhole manager service
/// (`wire.TxVersion`).
pub const TX_VERSION: u32 = 1;
/// Default input sequence (`wire.MaxTxInSequenceNum`).
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// Build a canonical P2PKH scriptPubKey:
/// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(0x76); // OP_DUP
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(pubkey_hash);
    s.push(0x88); // OP_EQUALVERIFY
    s.push(0xac); // OP_CHECKSIG
    s
}

/// Build a canonical P2SH scriptPubKey: `OP_HASH160 <20> OP_EQUAL`.
pub fn p2sh_script_pubkey(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(23);
    s.push(0xa9); // OP_HASH160
    s.push(0x14); // push 20 bytes
    s.extend_from_slice(script_hash);
    s.push(0x87); // OP_EQUAL
    s
}

/// Build the scriptPubKey for a UTXO output address type.
pub fn script_pub_key_for(addr_type: UtxoAddressType, address: &[u8]) -> Result<Vec<u8>> {
    match addr_type {
        UtxoAddressType::P2pkh => {
            let h: [u8; 20] = address
                .try_into()
                .map_err(|_| anyhow!("P2PKH address must be 20 bytes"))?;
            Ok(p2pkh_script_pubkey(&h))
        }
        UtxoAddressType::P2sh => {
            let h: [u8; 20] = address
                .try_into()
                .map_err(|_| anyhow!("P2SH address must be 20 bytes"))?;
            Ok(p2sh_script_pubkey(&h))
        }
    }
}

#[inline]
fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

#[derive(Debug, Clone)]
struct TxIn {
    prev_txid_le: [u8; 32], // internal little-endian (wire order)
    vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

#[derive(Debug, Clone)]
struct TxOut {
    value: u64,
    script_pubkey: Vec<u8>,
}

/// An unsigned (and later signed) Dogecoin transaction carrying the redeem
/// script used for each P2SH input.
#[derive(Debug, Clone)]
pub struct UnsignedTransaction {
    version: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    locktime: u32,
    /// Per-input redeem script (the subscript signed for P2SH).
    redeem_scripts: Vec<Vec<u8>>,
}

impl UnsignedTransaction {
    /// Build the unsigned transaction from a `UTX0` unlock payload.
    ///
    /// `redeem_scripts` must contain one redeem script per input (in the
    /// Wormhole flow each input has its own recipient, hence its own redeem
    /// script). The Wormhole `transaction_id` is big-endian and is reversed
    /// to the Bitcoin internal little-endian prevout hash, exactly as the Go
    /// `BuildUnsignedTransaction` does.
    pub fn from_utx0(payload: &Utx0UnlockPayload, redeem_scripts: Vec<Vec<u8>>) -> Result<Self> {
        if payload.inputs.is_empty() {
            bail!("no inputs in payload");
        }
        if payload.outputs.is_empty() {
            bail!("no outputs in payload");
        }
        if redeem_scripts.len() != payload.inputs.len() {
            bail!(
                "redeem_scripts count {} != inputs count {}",
                redeem_scripts.len(),
                payload.inputs.len()
            );
        }

        let mut inputs = Vec::with_capacity(payload.inputs.len());
        for input in &payload.inputs {
            // Reverse big-endian Wormhole txid -> Bitcoin little-endian prevout.
            let mut prev_txid_le = [0u8; 32];
            for i in 0..32 {
                prev_txid_le[i] = input.transaction_id[31 - i];
            }
            inputs.push(TxIn {
                prev_txid_le,
                vout: input.vout,
                script_sig: Vec::new(),
                sequence: SEQUENCE_FINAL,
            });
        }

        let mut outputs = Vec::with_capacity(payload.outputs.len());
        for (i, output) in payload.outputs.iter().enumerate() {
            let script_pubkey = script_pub_key_for(output.address_type, &output.address)
                .map_err(|e| anyhow!("output {i}: {e}"))?;
            outputs.push(TxOut {
                value: output.amount,
                script_pubkey,
            });
        }

        Ok(UnsignedTransaction {
            version: TX_VERSION,
            inputs,
            outputs,
            locktime: 0,
            redeem_scripts,
        })
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Compute the legacy SIGHASH_ALL sighash for `input_index`, using the
    /// input's redeem script as the signed subscript (P2SH semantics).
    ///
    /// This reproduces btcd `CalcSignatureHash(script, SigHashAll, tx, idx)`:
    /// copy the tx, blank every input's scriptSig, set the signed input's
    /// scriptSig to the redeem script, serialize (no witness), append the
    /// hash type as a little-endian u32, then double-SHA256.
    pub fn sighash_all(&self, input_index: usize) -> Result<[u8; 32]> {
        self.sighash(input_index, SIGHASH_ALL)
    }

    /// Legacy sighash for the given (base) hash type. Only `SIGHASH_ALL` is
    /// used by the relay, but `SIGHASH_NONE`/`SINGLE`/`ANYONECANPAY` are
    /// handled for fidelity with btcd's `calcSignatureHash`.
    pub fn sighash(&self, input_index: usize, hash_type: u32) -> Result<[u8; 32]> {
        if input_index >= self.inputs.len() {
            bail!(
                "input index {input_index} out of range [0, {})",
                self.inputs.len()
            );
        }
        let redeem_script = self
            .redeem_scripts
            .get(input_index)
            .ok_or_else(|| anyhow!("no redeem script for input {input_index}"))?;

        let base = hash_type & 0x1f;
        let anyone_can_pay = (hash_type & 0x80) != 0;

        // SIGHASH_SINGLE with idx >= output count => hash of "01" (btcd rule).
        if base == 0x03 && input_index >= self.outputs.len() {
            let preimage = [0x01u8];
            return Ok(double_sha256(&preimage));
        }

        // Build the modified copy.
        let mut inputs: Vec<TxIn> = if anyone_can_pay {
            vec![self.inputs[input_index].clone()]
        } else {
            self.inputs
                .iter()
                .map(|i| TxIn {
                    script_sig: Vec::new(),
                    sequence: i.sequence,
                    ..i.clone()
                })
                .collect()
        };

        // Set the signed input's scriptSig to the redeem script.
        let signed_idx = if anyone_can_pay { 0 } else { input_index };
        inputs[signed_idx].script_sig = redeem_script.clone();

        // For NONE/SINGLE, blank other inputs' sequences.
        if !anyone_can_pay && (base == 0x02 || base == 0x03) {
            for (i, inp) in inputs.iter_mut().enumerate() {
                if i != signed_idx {
                    inp.sequence = 0;
                }
            }
        }

        // For NONE, drop all outputs; for SINGLE, keep only the matching output.
        let outputs: Vec<TxOut> = match base {
            0x02 => Vec::new(),
            0x03 => self.outputs.get(input_index).cloned().into_iter().collect(),
            _ => self.outputs.clone(),
        };

        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut buf, inputs.len() as u64);
        for inp in &inputs {
            buf.extend_from_slice(&inp.prev_txid_le);
            buf.extend_from_slice(&inp.vout.to_le_bytes());
            write_varint(&mut buf, inp.script_sig.len() as u64);
            buf.extend_from_slice(&inp.script_sig);
            buf.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        write_varint(&mut buf, outputs.len() as u64);
        for out in &outputs {
            buf.extend_from_slice(&out.value.to_le_bytes());
            write_varint(&mut buf, out.script_pubkey.len() as u64);
            buf.extend_from_slice(&out.script_pubkey);
        }
        buf.extend_from_slice(&self.locktime.to_le_bytes());
        // Append hash type (little-endian u32) — legacy sighash convention.
        buf.extend_from_slice(&hash_type.to_le_bytes());

        Ok(double_sha256(&buf))
    }

    /// Apply the M aggregated signatures to `input_index`, producing the
    /// P2SH multisig scriptSig: `OP_0 <sig_1> ... <sig_M> <redeemScript>`.
    ///
    /// `signatures` must be ordered to match the redeem-script pubkey order
    /// and each must already be DER-encoded with the sighash type byte
    /// appended (as the manager service produces them).
    pub fn apply_script_sig(&mut self, input_index: usize, signatures: &[Vec<u8>]) -> Result<()> {
        if input_index >= self.inputs.len() {
            bail!("input index {input_index} out of range");
        }
        let redeem_script = self
            .redeem_scripts
            .get(input_index)
            .ok_or_else(|| anyhow!("no redeem script for input {input_index}"))?;

        let mut script_sig =
            Vec::with_capacity(1 + signatures.len() * 74 + 1 + redeem_script.len());
        script_sig.push(0x00); // OP_0 — CHECKMULTISIG off-by-one dummy
        for sig in signatures {
            push_data_inline(&mut script_sig, sig);
        }
        push_data_inline(&mut script_sig, redeem_script);
        self.inputs[input_index].script_sig = script_sig;
        Ok(())
    }

    /// Serialize the (signed) transaction for broadcast.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.inputs.len() * 40 + self.outputs.len() * 34);
        buf.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut buf, self.inputs.len() as u64);
        for inp in &self.inputs {
            buf.extend_from_slice(&inp.prev_txid_le);
            buf.extend_from_slice(&inp.vout.to_le_bytes());
            write_varint(&mut buf, inp.script_sig.len() as u64);
            buf.extend_from_slice(&inp.script_sig);
            buf.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        write_varint(&mut buf, self.outputs.len() as u64);
        for out in &self.outputs {
            buf.extend_from_slice(&out.value.to_le_bytes());
            write_varint(&mut buf, out.script_pubkey.len() as u64);
            buf.extend_from_slice(&out.script_pubkey);
        }
        buf.extend_from_slice(&self.locktime.to_le_bytes());
        buf
    }

    /// Standard txid: double-SHA256 of the serialized tx, reversed to
    /// big-endian display order.
    pub fn txid(&self) -> [u8; 32] {
        let mut h = double_sha256(&self.serialize());
        h.reverse();
        h
    }
}

#[inline]
fn push_data_inline(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 0x4b {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(0x4c);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x4d);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        buf.push(0x4e);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    }
    buf.extend_from_slice(data);
}

/// Bitcoin double-SHA256.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wormhole::utx0::{Utx0Input, Utx0Output, UtxoAddressType};

    fn a32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        hex::decode_to_slice(s, &mut a).unwrap();
        a
    }

    fn dummy_pubkeys() -> [[u8; 33]; 2] {
        let mut p1 = [0u8; 33];
        p1[0] = 0x02;
        let mut p2 = [0u8; 33];
        p2[0] = 0x03;
        [p1, p2]
    }

    fn sample_payload() -> Utx0UnlockPayload {
        Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 1,
            inputs: vec![Utx0Input {
                original_recipient_address: a32(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                ),
                transaction_id: a32(
                    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                ),
                vout: 0,
            }],
            outputs: vec![Utx0Output {
                amount: 1_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: hex::decode("55ae51684c43435da751ac8d2173b2652eb64105").unwrap(),
            }],
        }
    }

    #[test]
    fn build_unsigned_tx_structure() {
        let payload = sample_payload();
        let pks = dummy_pubkeys();
        let r = crate::wormhole::redeem::build_redeem_script(1u16, &[0u8; 32], &[0u8; 32], 2, &pks)
            .unwrap();
        let tx = UnsignedTransaction::from_utx0(&payload, vec![r]).unwrap();
        assert_eq!(tx.input_count(), 1);
        assert_eq!(tx.output_count(), 1);

        let ser = tx.serialize();
        // version = 1 (LE)
        assert_eq!(&ser[0..4], &[1u8, 0, 0, 0]);
        // input count = 1
        assert_eq!(ser[4], 1);
        // prevout hash is reversed txid
        let mut reversed = [0u8; 32];
        for i in 0..32 {
            reversed[i] = payload.inputs[0].transaction_id[31 - i];
        }
        assert_eq!(&ser[5..37], &reversed);
        // vout = 0 (LE)
        assert_eq!(&ser[37..41], &[0u8; 4]);
        // empty scriptSig length = 0
        assert_eq!(ser[41], 0);
        // sequence = 0xffffffff (LE)
        assert_eq!(&ser[42..46], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn sighash_all_is_nonzero_and_stable() {
        let payload = sample_payload();
        let pks = dummy_pubkeys();
        let r = crate::wormhole::redeem::build_redeem_script(1u16, &[0u8; 32], &[0u8; 32], 2, &pks)
            .unwrap();
        let tx = UnsignedTransaction::from_utx0(&payload, vec![r]).unwrap();
        let h0 = tx.sighash_all(0).unwrap();
        assert!(h0.iter().any(|b| *b != 0));
        assert_eq!(h0, tx.sighash_all(0).unwrap());
    }

    #[test]
    fn sighash_out_of_range_errors() {
        let payload = sample_payload();
        let tx = UnsignedTransaction::from_utx0(&payload, vec![vec![0x51]]).unwrap();
        assert!(tx.sighash_all(1).is_err());
    }

    #[test]
    fn two_inputs_yield_different_sighashes() {
        let payload = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 1,
            inputs: vec![
                Utx0Input {
                    original_recipient_address: [0u8; 32],
                    transaction_id: a32(
                        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    ),
                    vout: 0,
                },
                Utx0Input {
                    original_recipient_address: [0u8; 32],
                    transaction_id: a32(
                        "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
                    ),
                    vout: 1,
                },
            ],
            outputs: vec![Utx0Output {
                amount: 1_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: hex::decode("55ae51684c43435da751ac8d2173b2652eb64105").unwrap(),
            }],
        };
        let pks = dummy_pubkeys();
        let r = crate::wormhole::redeem::build_redeem_script(1u16, &[0u8; 32], &[0u8; 32], 2, &pks)
            .unwrap();
        let tx = UnsignedTransaction::from_utx0(&payload, vec![r.clone(), r]).unwrap();
        let h0 = tx.sighash_all(0).unwrap();
        let h1 = tx.sighash_all(1).unwrap();
        assert_ne!(h0, h1);
    }

    #[test]
    fn apply_script_sig_shape() {
        let payload = sample_payload();
        let pks = dummy_pubkeys();
        let r = crate::wormhole::redeem::build_redeem_script(1u16, &[0u8; 32], &[0u8; 32], 2, &pks)
            .unwrap();
        let redeem_len = r.len();
        let mut tx = UnsignedTransaction::from_utx0(&payload, vec![r.clone()]).unwrap();
        // two 8-byte DER+hashtype signatures
        let sig1 = vec![0x30u8, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01];
        let sig2 = vec![0x30u8, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04, 0x01];
        tx.apply_script_sig(0, &[sig1, sig2]).unwrap();
        let ser = tx.serialize();
        // version(4) + in_count(1) + prevout(32) + vout(4) + script_len(varint)
        let script_len_pos = 4 + 1 + 32 + 4;
        // scriptSig = OP_0(1) + push(1+8) + push(1+8) + push(redeem via PUSHDATA1: 2+redeem_len)
        let script_sig_len = 1 + 9 + 9 + (2 + redeem_len);
        assert_eq!(ser[script_len_pos], script_sig_len as u8);
        assert_eq!(ser[script_len_pos + 1], 0x00); // OP_0
        assert_eq!(ser[script_len_pos + 2], 8); // first sig length
                                                // tail: after scriptSig comes sequence(4) + out_count(1) + output(34)
                                                // + locktime(4). The redeem push (OP_PUSHDATA1 + len + redeem) sits
                                                // just before that trailing region.
        let tail_start = ser.len() - 4 - 34 - 1 - 4 - 2 - redeem_len;
        assert_eq!(ser[tail_start], 0x4c);
        assert_eq!(ser[tail_start + 1], redeem_len as u8);
        assert_eq!(&ser[tail_start + 2..tail_start + 2 + redeem_len], &r[..]);
        assert_eq!(&ser[ser.len() - 4..], &[0u8; 4]); // locktime
    }

    #[test]
    fn double_sha256_known_vector() {
        // double_sha256(b"hello") == sha256(sha256(b"hello"))
        let got = double_sha256(b"hello");
        let first = Sha256::digest(b"hello");
        let want: [u8; 32] = Sha256::digest(first).into();
        assert_eq!(got, want);
    }

    #[test]
    fn txid_is_double_sha256_reversed() {
        let payload = sample_payload();
        let pks = dummy_pubkeys();
        let r = crate::wormhole::redeem::build_redeem_script(1u16, &[0u8; 32], &[0u8; 32], 2, &pks)
            .unwrap();
        let tx = UnsignedTransaction::from_utx0(&payload, vec![r]).unwrap();
        let ser = tx.serialize();
        let mut want = double_sha256(&ser);
        want.reverse();
        assert_eq!(tx.txid(), want);
    }
}
