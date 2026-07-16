//! Wormhole operator/relay helpers for the Dogecoin UTXO bridge.
//!
//! This module implements the operator/relay side of the P0 Wormhole 联调:
//!   - [`utx0`]   — `UTX0` unlock-payload encode/decode (big-endian, matching
//!                  `wormhole/sdk/vaa/payloads.go`).
//!   - [`redeem`] — P2SH redeem-script builder byte-identical to
//!                  `wormhole/node/pkg/manager/dogecoin/script.go`.
//!   - [`manager`] — delegated manager set + guardian manager-service API
//!                   client (`/v1/manager/signed_vaa/...`).
//!   - [`tx`]     — legacy (pre-segwit) Dogecoin transaction builder,
//!                   SIGHASH_ALL sighash, scriptSig assembly and broadcast
//!                   serialization, mirroring `.../dogecoin/transaction.go`.
//!
//! All Wormhole-side integers are big-endian; the Bitcoin/Dogecoin wire
//! format (`tx`) remains little-endian per consensus.

pub mod manager;
pub mod redeem;
pub mod tx;
pub mod utx0;

/// Wormhole chain IDs used by the Dogecoin bridge.
///
/// Source: `wormhole/sdk/vaa/structs.go` (`ChainIDSolana = 1`,
/// `ChainIDDogecoin = 65`).
pub mod chain_id {
    pub const SOLANA: u16 = 1;
    pub const DOGECOIN: u16 = 65;
}
