//! Outputs-only `UTX0` withdrawal payload emitted by the Solana bridge.
//!
//! All integers are big-endian:
//!
//! ```text
//! "UTX0" || destination_chain:u16 || manager_set_index:u32
//!        || output_count:u32 || outputs[]
//!
//! output = amount:u64 || address_type:u32 || recipient_address:[u8;20]
//! ```

use anyhow::{anyhow, bail, Result};

pub const UTX0_PREFIX: [u8; 4] = *b"UTX0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum UtxoAddressType {
    P2pkh = 0,
    P2sh = 1,
}

impl UtxoAddressType {
    pub fn from_u32(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::P2pkh),
            1 => Ok(Self::P2sh),
            other => Err(anyhow!("unknown UTXO address type: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utx0Output {
    pub amount: u64,
    pub address_type: UtxoAddressType,
    pub address: [u8; 20],
}

impl Utx0Output {
    pub const SIZE: usize = 32;

    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..8].copy_from_slice(&self.amount.to_be_bytes());
        bytes[8..12].copy_from_slice(&(self.address_type as u32).to_be_bytes());
        bytes[12..32].copy_from_slice(&self.address);
        bytes
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            bail!(
                "UTX0 output too short: expected {} bytes, got {}",
                Self::SIZE,
                bytes.len()
            );
        }
        let amount = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let address_type =
            UtxoAddressType::from_u32(u32::from_be_bytes(bytes[8..12].try_into().unwrap()))?;
        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes[12..32]);
        Ok(Self {
            amount,
            address_type,
            address,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utx0UnlockPayload {
    pub destination_chain: u16,
    pub delegated_manager_set_index: u32,
    pub outputs: Vec<Utx0Output>,
}

impl Utx0UnlockPayload {
    const HEADER_SIZE: usize = 14;

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let output_count = u32::try_from(self.outputs.len())
            .map_err(|_| anyhow!("too many outputs: {}", self.outputs.len()))?;
        let capacity = Self::HEADER_SIZE
            .checked_add(
                self.outputs
                    .len()
                    .checked_mul(Utx0Output::SIZE)
                    .ok_or_else(|| anyhow!("UTX0 payload size overflow"))?,
            )
            .ok_or_else(|| anyhow!("UTX0 payload size overflow"))?;

        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&UTX0_PREFIX);
        bytes.extend_from_slice(&self.destination_chain.to_be_bytes());
        bytes.extend_from_slice(&self.delegated_manager_set_index.to_be_bytes());
        bytes.extend_from_slice(&output_count.to_be_bytes());
        for output in &self.outputs {
            bytes.extend_from_slice(&output.serialize());
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::HEADER_SIZE {
            bail!(
                "UTX0 unlock payload too short: expected at least {} bytes, got {}",
                Self::HEADER_SIZE,
                bytes.len()
            );
        }
        if bytes[0..4] != UTX0_PREFIX {
            bail!("invalid UTX0 payload prefix");
        }

        let destination_chain = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let delegated_manager_set_index = u32::from_be_bytes(bytes[6..10].try_into().unwrap());
        let output_count = u32::from_be_bytes(bytes[10..14].try_into().unwrap()) as usize;
        let expected_size = Self::HEADER_SIZE
            .checked_add(
                output_count
                    .checked_mul(Utx0Output::SIZE)
                    .ok_or_else(|| anyhow!("UTX0 output count overflow"))?,
            )
            .ok_or_else(|| anyhow!("UTX0 payload size overflow"))?;
        if bytes.len() != expected_size {
            bail!(
                "UTX0 unlock payload length mismatch: expected {expected_size} bytes, got {}",
                bytes.len()
            );
        }

        let outputs = bytes[Self::HEADER_SIZE..]
            .chunks_exact(Utx0Output::SIZE)
            .enumerate()
            .map(|(index, bytes)| {
                Utx0Output::parse(bytes)
                    .map_err(|error| anyhow!("failed to parse output {index}: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            destination_chain,
            delegated_manager_set_index,
            outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(seed: u8, amount: u64, address_type: UtxoAddressType) -> Utx0Output {
        Utx0Output {
            amount,
            address_type,
            address: [seed; 20],
        }
    }

    #[test]
    fn round_trip_matches_core_wire_order() {
        let payload = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 7,
            outputs: vec![output(0x11, 1_000_000, UtxoAddressType::P2pkh)],
        };
        let bytes = payload.serialize().unwrap();
        assert_eq!(bytes.len(), 46);
        assert_eq!(&bytes[0..4], b"UTX0");
        assert_eq!(&bytes[4..6], &65u16.to_be_bytes());
        assert_eq!(&bytes[6..10], &7u32.to_be_bytes());
        assert_eq!(&bytes[10..14], &1u32.to_be_bytes());
        assert_eq!(&bytes[14..22], &1_000_000u64.to_be_bytes());
        assert_eq!(&bytes[22..26], &0u32.to_be_bytes());
        assert_eq!(&bytes[26..46], &[0x11; 20]);
        assert_eq!(Utx0UnlockPayload::parse(&bytes).unwrap(), payload);
    }

    #[test]
    fn round_trip_multiple_outputs() {
        let payload = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 1,
            outputs: vec![
                output(0x22, 5_000, UtxoAddressType::P2pkh),
                output(0x33, 9_000, UtxoAddressType::P2sh),
            ],
        };
        let bytes = payload.serialize().unwrap();
        assert_eq!(Utx0UnlockPayload::parse(&bytes).unwrap(), payload);
    }

    #[test]
    fn rejects_invalid_lengths_and_address_type() {
        let mut bytes = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 0,
            outputs: vec![output(0x44, 1, UtxoAddressType::P2pkh)],
        }
        .serialize()
        .unwrap();
        bytes[22..26].copy_from_slice(&9u32.to_be_bytes());
        assert!(Utx0UnlockPayload::parse(&bytes).is_err());
        bytes[22..26].copy_from_slice(&0u32.to_be_bytes());
        bytes.push(0xff);
        assert!(Utx0UnlockPayload::parse(&bytes).is_err());
    }
}
