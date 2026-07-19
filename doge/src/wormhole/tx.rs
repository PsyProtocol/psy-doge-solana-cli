//! Dogecoin transaction construction for outputs-only UTX0 withdrawals.
//!
//! The operator selects custody UTXOs, then constructs the exact unsigned
//! transaction sent to the Manager service for input signing.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

use super::utx0::UtxoAddressType;

pub const SIGHASH_ALL: u32 = 0x01;
pub const TX_VERSION: u32 = 1;
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const MAX_PERSISTED_INPUTS: usize = 1_000;
const MAX_PERSISTED_OUTPUTS: usize = 320;
const MAX_STANDARD_OUTPUT_SCRIPT_LEN: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedUtxo {
    /// Dogecoin display-order transaction ID. It is reversed for wire encoding.
    pub transaction_id: [u8; 32],
    pub vout: u32,
    pub redeem_script: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionOutput {
    pub amount: u64,
    pub address_type: UtxoAddressType,
    pub address: [u8; 20],
}

pub fn p2pkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(pubkey_hash);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

pub fn p2sh_script_pubkey(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(23);
    script.extend_from_slice(&[0xa9, 0x14]);
    script.extend_from_slice(script_hash);
    script.push(0x87);
    script
}

pub fn script_pub_key_for(address_type: UtxoAddressType, address: &[u8; 20]) -> Vec<u8> {
    match address_type {
        UtxoAddressType::P2pkh => p2pkh_script_pubkey(address),
        UtxoAddressType::P2sh => p2sh_script_pubkey(address),
    }
}

#[inline]
fn write_varint(bytes: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        bytes.push(value as u8);
    } else if value <= 0xffff {
        bytes.push(0xfd);
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        bytes.push(0xfe);
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        bytes.push(0xff);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

#[derive(Debug, Clone)]
struct TxIn {
    prev_txid_le: [u8; 32],
    vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

#[derive(Debug, Clone)]
struct TxOut {
    value: u64,
    script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UnsignedTransaction {
    version: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    logical_outputs: Vec<TransactionOutput>,
    locktime: u32,
    redeem_scripts: Vec<Vec<u8>>,
}

impl UnsignedTransaction {
    pub fn new(inputs: Vec<SelectedUtxo>, outputs: Vec<TransactionOutput>) -> Result<Self> {
        if inputs.is_empty() {
            bail!("no selected inputs");
        }
        if outputs.is_empty() {
            bail!("no outputs");
        }

        let mut tx_inputs = Vec::with_capacity(inputs.len());
        let mut redeem_scripts = Vec::with_capacity(inputs.len());
        for input in inputs {
            let mut prev_txid_le = input.transaction_id;
            prev_txid_le.reverse();
            tx_inputs.push(TxIn {
                prev_txid_le,
                vout: input.vout,
                script_sig: Vec::new(),
                sequence: SEQUENCE_FINAL,
            });
            redeem_scripts.push(input.redeem_script);
        }

        let tx_outputs = outputs
            .iter()
            .map(|output| TxOut {
                value: output.amount,
                script_pubkey: script_pub_key_for(output.address_type, &output.address),
            })
            .collect();

        Ok(Self {
            version: TX_VERSION,
            inputs: tx_inputs,
            outputs: tx_outputs,
            logical_outputs: outputs,
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

    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.logical_outputs
    }

    pub fn sighash_all(&self, input_index: usize) -> Result<[u8; 32]> {
        self.sighash(input_index, SIGHASH_ALL)
    }

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

        if base == 0x03 && input_index >= self.outputs.len() {
            return Ok(double_sha256(&[0x01]));
        }

        let mut inputs = if anyone_can_pay {
            vec![self.inputs[input_index].clone()]
        } else {
            self.inputs
                .iter()
                .map(|input| TxIn {
                    script_sig: Vec::new(),
                    ..input.clone()
                })
                .collect::<Vec<_>>()
        };
        let signed_index = if anyone_can_pay { 0 } else { input_index };
        inputs[signed_index].script_sig = redeem_script.clone();
        if !anyone_can_pay && (base == 0x02 || base == 0x03) {
            for (index, input) in inputs.iter_mut().enumerate() {
                if index != signed_index {
                    input.sequence = 0;
                }
            }
        }

        let outputs = match base {
            0x02 => Vec::new(),
            0x03 => self.outputs.get(input_index).cloned().into_iter().collect(),
            _ => self.outputs.clone(),
        };
        let mut bytes = serialize_transaction(self.version, &inputs, &outputs, self.locktime);
        bytes.extend_from_slice(&hash_type.to_le_bytes());
        Ok(double_sha256(&bytes))
    }

    pub fn apply_script_sig(&mut self, input_index: usize, signatures: &[Vec<u8>]) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or_else(|| anyhow!("input index {input_index} out of range"))?;
        let redeem_script = self
            .redeem_scripts
            .get(input_index)
            .ok_or_else(|| anyhow!("no redeem script for input {input_index}"))?;
        let mut script_sig =
            Vec::with_capacity(1 + signatures.len() * 74 + redeem_script.len() + 2);
        script_sig.push(0x00);
        for signature in signatures {
            push_data_inline(&mut script_sig, signature);
        }
        push_data_inline(&mut script_sig, redeem_script);
        input.script_sig = script_sig;
        Ok(())
    }
    /// Recover an unsigned transaction from durable wire bytes and independently
    /// reconstructed selected inputs. Redeem scripts come from `inputs`, so
    /// sighash construction remains available after restart without persisting
    /// private key material.
    pub fn from_persisted_bytes(bytes: &[u8], inputs: Vec<SelectedUtxo>) -> Result<Self> {
        if inputs.is_empty() {
            bail!("no selected inputs");
        }
        let mut reader = TransactionReader::new(bytes);
        let version = reader.read_u32("version")?;
        if version != TX_VERSION {
            bail!("unsupported persisted transaction version {version}");
        }
        let input_count = reader.read_count("input count")?;
        if input_count > MAX_PERSISTED_INPUTS {
            bail!("persisted transaction input count {input_count} exceeds safety limit");
        }
        if input_count != inputs.len() {
            bail!(
                "persisted transaction has {input_count} inputs, reservation has {}",
                inputs.len()
            );
        }

        let mut tx_inputs = Vec::with_capacity(input_count);
        let mut redeem_scripts = Vec::with_capacity(input_count);
        for (index, selected) in inputs.into_iter().enumerate() {
            let prev_txid_le: [u8; 32] = reader
                .read_exact(32, "input transaction id")?
                .try_into()
                .expect("exact transaction id length");
            let vout = reader.read_u32("input vout")?;
            let script_len = reader.read_count("input script length")?;
            if script_len != 0 {
                bail!("persisted unsigned input {index} contains a scriptSig");
            }
            let sequence = reader.read_u32("input sequence")?;
            if sequence != SEQUENCE_FINAL {
                bail!("persisted unsigned input {index} has non-final sequence");
            }
            let mut expected_prev_txid_le = selected.transaction_id;
            expected_prev_txid_le.reverse();
            if prev_txid_le != expected_prev_txid_le || vout != selected.vout {
                bail!("persisted unsigned input {index} differs from custody reservation");
            }
            tx_inputs.push(TxIn {
                prev_txid_le,
                vout,
                script_sig: Vec::new(),
                sequence,
            });
            redeem_scripts.push(selected.redeem_script);
        }

        let output_count = reader.read_count("output count")?;
        if output_count > MAX_PERSISTED_OUTPUTS {
            bail!("persisted transaction output count {output_count} exceeds safety limit");
        }
        if output_count == 0 {
            bail!("persisted unsigned transaction has no outputs");
        }
        let mut outputs = Vec::with_capacity(output_count);
        let mut logical_outputs = Vec::with_capacity(output_count);
        for index in 0..output_count {
            let value = reader.read_u64("output value")?;
            let script_len = reader.read_count("output script length")?;
            if script_len > MAX_STANDARD_OUTPUT_SCRIPT_LEN {
                bail!("persisted output {index} scriptPubKey exceeds safety limit");
            }
            let script_pubkey = reader
                .read_exact(script_len, "output scriptPubKey")?
                .to_vec();
            let (address_type, address) = parse_standard_output(&script_pubkey)
                .with_context(|| format!("decode persisted output {index}"))?;
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
            logical_outputs.push(TransactionOutput {
                amount: value,
                address_type,
                address,
            });
        }
        let locktime = reader.read_u32("locktime")?;
        if locktime != 0 {
            bail!("persisted unsigned transaction has nonzero locktime");
        }
        reader.finish()?;

        let transaction = Self {
            version,
            inputs: tx_inputs,
            outputs,
            logical_outputs,
            locktime,
            redeem_scripts,
        };
        if transaction.serialize() != bytes {
            bail!("persisted unsigned transaction is not canonically encoded");
        }
        Ok(transaction)
    }

    pub fn serialize(&self) -> Vec<u8> {
        serialize_transaction(self.version, &self.inputs, &self.outputs, self.locktime)
    }

    pub fn txid(&self) -> [u8; 32] {
        let mut txid = double_sha256(&self.serialize());
        txid.reverse();
        txid
    }
}

fn parse_standard_output(script: &[u8]) -> Result<(UtxoAddressType, [u8; 20])> {
    let (address_type, payload) = if script.len() == 25
        && script[..3] == [0x76, 0xa9, 0x14]
        && script[23..] == [0x88, 0xac]
    {
        (UtxoAddressType::P2pkh, &script[3..23])
    } else if script.len() == 23 && script[..2] == [0xa9, 0x14] && script[22] == 0x87 {
        (UtxoAddressType::P2sh, &script[2..22])
    } else {
        bail!("unsupported output scriptPubKey")
    };
    let mut address = [0u8; 20];
    address.copy_from_slice(payload);
    Ok((address_type, address))
}

struct TransactionReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TransactionReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, len: usize, field: &str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("persisted transaction {field} length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| anyhow!("persisted transaction is truncated at {field}"))?;
        self.offset = end;
        Ok(value)
    }

    fn read_u32(&mut self, field: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.read_exact(4, field)?.try_into().expect("exact u32 length"),
        ))
    }

    fn read_u64(&mut self, field: &str) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.read_exact(8, field)?.try_into().expect("exact u64 length"),
        ))
    }

    fn read_count(&mut self, field: &str) -> Result<usize> {
        let first = self.read_exact(1, field)?[0];
        let value = match first {
            0x00..=0xfc => u64::from(first),
            0xfd => {
                let value = u16::from_le_bytes(
                    self.read_exact(2, field)?.try_into().expect("exact u16 length"),
                );
                if value < 0xfd {
                    bail!("persisted transaction {field} uses a non-canonical varint");
                }
                u64::from(value)
            }
            0xfe => {
                let value = self.read_u32(field)?;
                if value <= u32::from(u16::MAX) {
                    bail!("persisted transaction {field} uses a non-canonical varint");
                }
                u64::from(value)
            }
            0xff => {
                let value = self.read_u64(field)?;
                if value <= u64::from(u32::MAX) {
                    bail!("persisted transaction {field} uses a non-canonical varint");
                }
                value
            }
        };
        usize::try_from(value)
            .map_err(|_| anyhow!("persisted transaction {field} exceeds platform limits"))
    }

    fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            bail!("persisted transaction has trailing bytes");
        }
        Ok(())
    }
}

fn serialize_transaction(
    version: u32,
    inputs: &[TxIn],
    outputs: &[TxOut],
    locktime: u32,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + inputs.len() * 40 + outputs.len() * 34);
    bytes.extend_from_slice(&version.to_le_bytes());
    write_varint(&mut bytes, inputs.len() as u64);
    for input in inputs {
        bytes.extend_from_slice(&input.prev_txid_le);
        bytes.extend_from_slice(&input.vout.to_le_bytes());
        write_varint(&mut bytes, input.script_sig.len() as u64);
        bytes.extend_from_slice(&input.script_sig);
        bytes.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_varint(&mut bytes, outputs.len() as u64);
    for output in outputs {
        bytes.extend_from_slice(&output.value.to_le_bytes());
        write_varint(&mut bytes, output.script_pubkey.len() as u64);
        bytes.extend_from_slice(&output.script_pubkey);
    }
    bytes.extend_from_slice(&locktime.to_le_bytes());
    bytes
}

fn push_data_inline(bytes: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 0x4b {
        bytes.push(len as u8);
    } else if len <= 0xff {
        bytes.extend_from_slice(&[0x4c, len as u8]);
    } else if len <= 0xffff {
        bytes.push(0x4d);
        bytes.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        bytes.push(0x4e);
        bytes.extend_from_slice(&(len as u32).to_le_bytes());
    }
    bytes.extend_from_slice(data);
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(seed: u8, vout: u32) -> SelectedUtxo {
        SelectedUtxo {
            transaction_id: [seed; 32],
            vout,
            redeem_script: vec![0x51],
        }
    }

    fn output(seed: u8) -> TransactionOutput {
        TransactionOutput {
            amount: 1_000_000,
            address_type: UtxoAddressType::P2pkh,
            address: [seed; 20],
        }
    }

    #[test]
    fn builds_after_operator_selects_inputs() {
        let tx = UnsignedTransaction::new(vec![selected(0x22, 3)], vec![output(0x55)]).unwrap();
        assert_eq!(tx.input_count(), 1);
        assert_eq!(tx.output_count(), 1);
        assert_eq!(tx.outputs(), &[output(0x55)]);
        let bytes = tx.serialize();
        assert_eq!(&bytes[0..4], &TX_VERSION.to_le_bytes());
        assert_eq!(bytes[4], 1);
        assert_eq!(&bytes[5..37], &[0x22; 32]);
        assert_eq!(&bytes[37..41], &3u32.to_le_bytes());
    }

    #[test]
    fn selected_inputs_have_distinct_sighashes() {
        let tx = UnsignedTransaction::new(
            vec![selected(0x11, 0), selected(0x22, 1)],
            vec![output(0x55)],
        )
        .unwrap();
        assert_ne!(tx.sighash_all(0).unwrap(), tx.sighash_all(1).unwrap());
    }

    #[test]
    fn rejects_missing_selected_inputs_or_outputs() {
        assert!(UnsignedTransaction::new(Vec::new(), vec![output(0x55)]).is_err());
        assert!(UnsignedTransaction::new(vec![selected(0x11, 0)], Vec::new()).is_err());
    }

    #[test]
    fn applies_script_sig_and_computes_txid() {
        let mut tx = UnsignedTransaction::new(vec![selected(0x11, 0)], vec![output(0x55)]).unwrap();
        tx.apply_script_sig(0, &[vec![0x30, 0x01]]).unwrap();
        let mut expected = double_sha256(&tx.serialize());
        expected.reverse();
        assert_eq!(tx.txid(), expected);
    }
    #[test]
    fn recovers_prepare_style_persisted_transaction_with_sighash_material() {
        let mut store_txid_a = [0u8; 32];
        let mut store_txid_b = [0u8; 32];
        for (index, byte) in store_txid_a.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for (index, byte) in store_txid_b.iter_mut().enumerate() {
            *byte = (31 - index) as u8;
        }
        let inputs = [store_txid_a, store_txid_b]
            .into_iter()
            .enumerate()
            .map(|(vout, mut transaction_id)| {
                // Match `prepare_transaction`'s conversion from store txid order.
                transaction_id.reverse();
                SelectedUtxo {
                    transaction_id,
                    vout: vout as u32,
                    redeem_script: vec![0x51, vout as u8],
                }
            })
            .collect::<Vec<_>>();
        let original = UnsignedTransaction::new(inputs.clone(), vec![output(0x55)]).unwrap();
        let bytes = original.serialize();
        assert_eq!(&bytes[5..37], &store_txid_a);
        let recovered = UnsignedTransaction::from_persisted_bytes(&bytes, inputs).unwrap();
        assert_eq!(recovered.serialize(), bytes);
        assert_eq!(recovered.outputs(), original.outputs());
        assert_eq!(recovered.sighash_all(0).unwrap(), original.sighash_all(0).unwrap());
        assert_eq!(recovered.sighash_all(1).unwrap(), original.sighash_all(1).unwrap());
    }

    #[test]
    fn rejects_persisted_unsigned_transaction_drift() {
        let inputs = vec![selected(0x11, 0)];
        let original = UnsignedTransaction::new(inputs.clone(), vec![output(0x55)]).unwrap();
        let mut bytes = original.serialize();
        bytes[37] ^= 1;
        assert!(UnsignedTransaction::from_persisted_bytes(&bytes, inputs).is_err());
    }

}
