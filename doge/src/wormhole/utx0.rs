//! `UTX0` unlock payload — Wormhole VAA payload for unlocking funds on a
//! UTXO chain (Dogecoin).
//!
//! Wire format is byte-identical to `wormhole/sdk/vaa/payloads.go`
//! (`UTXOInput` / `UTXOOutput` / `UTXOUnlockPayload`). All integer fields are
//! encoded **big-endian**, as required by the Wormhole SDK.
//!
//! ```text
//! UTX0UnlockPayload:
//!   "UTX0"                       (4 bytes prefix)
//!   destination_chain            (u16 BE)
//!   delegated_manager_set_index  (u32 BE)
//!   len(inputs)                  (u32 BE)
//!   inputs[len]                  (each 68 bytes, see below)
//!   len(outputs)                 (u32 BE)
//!   outputs[len]                 (variable, see below)
//!
//! UTXOInput (68 bytes):
//!   original_recipient_address   (32 bytes)
//!   transaction_id               (32 bytes, big-endian txid)
//!   vout                         (u32 BE)
//!
//! UTXOOutput (12 + addr_len):
//!   amount                       (u64 BE)
//!   address_type                 (u32 BE)
//!   address                      (addr_len bytes; 20 for P2PKH/P2SH)
//! ```

use anyhow::{anyhow, bail, Result};

/// 4-byte payload prefix that dispatches UTXO unlock payloads.
pub const UTX0_PREFIX: [u8; 4] = *b"UTX0";

/// UTXO address type carried in [`Utx0Output`].
///
/// Matches `UTXOAddressType` in `payloads.go` (`P2PKH = 0`, `P2SH = 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum UtxoAddressType {
    P2pkh = 0,
    P2sh = 1,
}

impl UtxoAddressType {
    pub fn address_length(self) -> Option<usize> {
        match self {
            UtxoAddressType::P2pkh | UtxoAddressType::P2sh => Some(20),
        }
    }

    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            0 => Ok(UtxoAddressType::P2pkh),
            1 => Ok(UtxoAddressType::P2sh),
            other => Err(anyhow!("unknown UTXO address type: {other}")),
        }
    }
}

/// A UTXO to spend. `transaction_id` is the big-endian Wormhole txid
/// (the natural byte order used by the SDK; relay code reverses it to the
/// Bitcoin internal little-endian order when building the wire transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utx0Input {
    pub original_recipient_address: [u8; 32],
    pub transaction_id: [u8; 32],
    pub vout: u32,
}

impl Utx0Input {
    /// Fixed serialized size: 32 + 32 + 4 = 68 bytes.
    pub const SIZE: usize = 68;

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.original_recipient_address);
        buf[32..64].copy_from_slice(&self.transaction_id);
        buf[64..68].copy_from_slice(&self.vout.to_be_bytes());
        buf
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            bail!(
                "UTX0 input too short: expected {} bytes, got {}",
                Self::SIZE,
                bytes.len()
            );
        }
        let mut original_recipient_address = [0u8; 32];
        original_recipient_address.copy_from_slice(&bytes[0..32]);
        let mut transaction_id = [0u8; 32];
        transaction_id.copy_from_slice(&bytes[32..64]);
        let vout = u32::from_be_bytes(bytes[64..68].try_into().unwrap());
        Ok(Utx0Input {
            original_recipient_address,
            transaction_id,
            vout,
        })
    }
}

/// A destination for unlocked funds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utx0Output {
    pub amount: u64,
    pub address_type: UtxoAddressType,
    pub address: Vec<u8>,
}

impl Utx0Output {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let addr_len = self
            .address_type
            .address_length()
            .ok_or_else(|| anyhow!("cannot serialize unknown address type"))?;
        if self.address.len() != addr_len {
            bail!(
                "address length mismatch: expected {addr_len} bytes for type {:?}, got {}",
                self.address_type,
                self.address.len()
            );
        }
        let mut buf = Vec::with_capacity(12 + addr_len);
        buf.extend_from_slice(&self.amount.to_be_bytes());
        buf.extend_from_slice(&(self.address_type as u32).to_be_bytes());
        buf.extend_from_slice(&self.address);
        Ok(buf)
    }

    /// Parse one output, returning it together with the number of bytes
    /// consumed (so callers can advance through a concatenation of outputs).
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 12 {
            bail!(
                "UTX0 output too short: expected at least 12 bytes, got {}",
                bytes.len()
            );
        }
        let amount = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let address_type =
            UtxoAddressType::from_u32(u32::from_be_bytes(bytes[8..12].try_into().unwrap()))?;
        let addr_len = address_type
            .address_length()
            .ok_or_else(|| anyhow!("unknown address length for type {:?}", address_type))?;
        let total = 12 + addr_len;
        if bytes.len() < total {
            bail!(
                "UTX0 output too short for address: expected {total} bytes, got {}",
                bytes.len()
            );
        }
        let mut address = vec![0u8; addr_len];
        address.copy_from_slice(&bytes[12..total]);
        Ok((
            Utx0Output {
                amount,
                address_type,
                address,
            },
            total,
        ))
    }
}

/// The full `UTX0` unlock payload emitted by a registered emitter to trigger
/// manager-service signing on a UTXO chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utx0UnlockPayload {
    pub destination_chain: u16,
    pub delegated_manager_set_index: u32,
    pub inputs: Vec<Utx0Input>,
    pub outputs: Vec<Utx0Output>,
}

impl Utx0UnlockPayload {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        if self.inputs.len() > u32::MAX as usize {
            bail!("too many inputs: {}", self.inputs.len());
        }
        if self.outputs.len() > u32::MAX as usize {
            bail!("too many outputs: {}", self.outputs.len());
        }
        let mut buf = Vec::with_capacity(18 + self.inputs.len() * Utx0Input::SIZE);
        buf.extend_from_slice(&UTX0_PREFIX);
        buf.extend_from_slice(&self.destination_chain.to_be_bytes());
        buf.extend_from_slice(&self.delegated_manager_set_index.to_be_bytes());
        buf.extend_from_slice(&(self.inputs.len() as u32).to_be_bytes());
        for input in &self.inputs {
            buf.extend_from_slice(&input.serialize());
        }
        buf.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for output in &self.outputs {
            buf.extend_from_slice(&output.serialize()?);
        }
        Ok(buf)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // prefix(4) + chain(2) + manager_set(4) + len_in(4) + len_out(4) = 18
        const MIN_SIZE: usize = 18;
        if bytes.len() < MIN_SIZE {
            bail!(
                "UTX0 unlock payload too short: expected at least {MIN_SIZE} bytes, got {}",
                bytes.len()
            );
        }
        if bytes[0..4] != UTX0_PREFIX {
            bail!(
                "invalid UTX0 payload prefix: expected {:?}, got {:?}",
                &UTX0_PREFIX[..],
                &bytes[0..4]
            );
        }
        let mut off = 4;
        let destination_chain = u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        let delegated_manager_set_index =
            u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
        off += 4;

        let len_input = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let remaining = bytes.len() - off;
        if len_input * Utx0Input::SIZE > remaining {
            bail!("UTX0 input count {len_input} exceeds remaining {remaining} bytes");
        }
        let mut inputs = Vec::with_capacity(len_input);
        for i in 0..len_input {
            let input = Utx0Input::parse(&bytes[off..])
                .map_err(|e| anyhow!("failed to parse input {i}: {e}"))?;
            inputs.push(input);
            off += Utx0Input::SIZE;
        }

        if off + 4 > bytes.len() {
            bail!("UTX0 unlock payload truncated while reading output count");
        }
        let len_output = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut outputs = Vec::with_capacity(len_output);
        for i in 0..len_output {
            let (output, size) = Utx0Output::parse(&bytes[off..])
                .map_err(|e| anyhow!("failed to parse output {i}: {e}"))?;
            outputs.push(output);
            off += size;
        }

        if off != bytes.len() {
            bail!(
                "UTX0 unlock payload has trailing bytes: consumed {off} of {} bytes",
                bytes.len()
            );
        }

        Ok(Utx0UnlockPayload {
            destination_chain,
            delegated_manager_set_index,
            inputs,
            outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        hex::decode_to_slice(s, &mut a).unwrap();
        a
    }

    #[test]
    fn round_trip_single_input_output() {
        let payload = Utx0UnlockPayload {
            destination_chain: chain_id_helpers::DOGECOIN,
            delegated_manager_set_index: 1,
            inputs: vec![Utx0Input {
                original_recipient_address: hex32(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                ),
                transaction_id: hex32(
                    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                ),
                vout: 0,
            }],
            outputs: vec![Utx0Output {
                amount: 1_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: hex::decode("55ae51684c43435da751ac8d2173b2652eb64105").unwrap(),
            }],
        };

        let bytes = payload.serialize().unwrap();
        // prefix(4)+chain(2)+manager(4)+len_in(4)+input(68)+len_out(4)+output(32)
        assert_eq!(bytes.len(), 4 + 2 + 4 + 4 + 68 + 4 + 32);
        assert_eq!(&bytes[0..4], b"UTX0");

        let decoded = Utx0UnlockPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn round_trip_multi_input_output() {
        let payload = Utx0UnlockPayload {
            destination_chain: chain_id_helpers::DOGECOIN,
            delegated_manager_set_index: 7,
            inputs: vec![
                Utx0Input {
                    original_recipient_address: hex32(
                        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    ),
                    transaction_id: hex32(
                        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
                    ),
                    vout: 0,
                },
                Utx0Input {
                    original_recipient_address: [0u8; 32],
                    transaction_id: hex32(
                        "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
                    ),
                    vout: 1,
                },
            ],
            outputs: vec![
                Utx0Output {
                    amount: 1_000_000,
                    address_type: UtxoAddressType::P2pkh,
                    address: hex::decode("55ae51684c43435da751ac8d2173b2652eb64105").unwrap(),
                },
                Utx0Output {
                    amount: 5_000,
                    address_type: UtxoAddressType::P2sh,
                    address: hex::decode("1122334455667788990011223344556677889900").unwrap(),
                },
            ],
        };
        let bytes = payload.serialize().unwrap();
        let decoded = Utx0UnlockPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_bad_prefix() {
        let mut bytes = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 0,
            inputs: vec![],
            outputs: vec![],
        }
        .serialize()
        .unwrap();
        bytes[0] = b'X';
        assert!(Utx0UnlockPayload::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 0,
            inputs: vec![],
            outputs: vec![],
        }
        .serialize()
        .unwrap();
        bytes.push(0xff);
        assert!(Utx0UnlockPayload::parse(&bytes).is_err());
    }

    // local helper so tests do not depend on the crate root chain_id module path
    mod chain_id_helpers {
        pub const DOGECOIN: u16 = 65;
    }
}
