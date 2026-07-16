//! Delegated manager set, guardian API client, and local-regtest manager service
//! primitives for the Dogecoin Wormhole relay.
//!
//! [`LOCAL_REGTEST_MANAGER_SET_PUBKEYS`] is intentionally local-only: its
//! public keys are derived from fixed private scalars embedded in this module
//! so a deterministic regtest service can sign the same transaction the relay
//! reconstructs. These keys MUST NOT protect public-network funds.
//!
//! [`fetch_manager_signatures`] calls the manager-service REST API
//! `GET /v1/manager/signed_vaa/{chain}/{emitter}/{sequence}` (path params) and
//! decodes the aggregated per-input signatures + the metadata the relay needs
//! to join against the separately-fetched signed VAA ([`fetch_signed_vaa`]).
//! The manager response does NOT contain the VAA bytes; per-input signatures
//! arrive base64-encoded (protobuf `bytes` JSON mapping). **Never trust
//! `isComplete` alone** — verify every signature locally with
//! [`verify_manager_signature`].
use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use super::{
    chain_id,
    redeem::build_redeem_script,
    tx::{UnsignedTransaction, SIGHASH_ALL},
    utx0::Utx0UnlockPayload,
};

/// A delegated secp256k1 multisig manager set for a UTXO chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerSet {
    pub m: u8,
    pub n: u8,
    pub pubkeys: Vec<[u8; 33]>,
}

impl ManagerSet {
    /// Parse the on-chain `Secp256k1MultisigManagerSet` byte layout:
    /// `Type(1) | M(1) | N(1) | PublicKeys(N*33)`. `Type` is currently
    /// ignored (only one manager-set type exists today), matching the Go
    /// `parseManagerSetBytes` behavior.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 3 {
            bail!("manager set too short: {} bytes", bytes.len());
        }
        let _ty = bytes[0];
        let m = bytes[1];
        let n = bytes[2] as usize;
        if bytes.len() < 3 + n * 33 {
            bail!(
                "manager set truncated: need {} bytes for {n} pubkeys, got {}",
                3 + n * 33,
                bytes.len()
            );
        }
        let mut pubkeys = Vec::with_capacity(n);
        for i in 0..n {
            let mut pk = [0u8; 33];
            pk.copy_from_slice(&bytes[3 + i * 33..3 + (i + 1) * 33]);
            pubkeys.push(pk);
        }
        Ok(ManagerSet {
            m,
            n: n as u8,
            pubkeys,
        })
    }

    /// Serialize back to the on-chain layout (Type = 0).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + self.pubkeys.len() * 33);
        buf.push(0u8); // Secp256k1MultisigManagerSet type tag
        buf.push(self.m);
        buf.push(self.n);
        for pk in &self.pubkeys {
            buf.extend_from_slice(pk);
        }
        buf
    }
}

/// Signature threshold for the deterministic local-regtest fixture.
pub const LOCAL_REGTEST_MANAGER_SET_M: u8 = 5;
/// Signer count for the deterministic local-regtest fixture.
pub const LOCAL_REGTEST_MANAGER_SET_N: u8 = 7;

/// Fixed private scalars used only by the local-regtest manager service.
///
/// Small non-zero scalars are valid secp256k1 secret keys and keep the fixture
/// independently reproducible. Never use these keys outside isolated regtest.
const LOCAL_REGTEST_MANAGER_PRIVATE_KEYS: [[u8; 32]; 7] = [
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 4,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 5,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 6,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 7,
    ],
];

/// Valid compressed public keys derived from
/// [`LOCAL_REGTEST_MANAGER_PRIVATE_KEYS`].
pub static LOCAL_REGTEST_MANAGER_SET_PUBKEYS: [[u8; 33]; 7] = [
    [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ],
    [
        0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0,
        0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c,
        0x70, 0x9e, 0xe5,
    ],
    [
        0x02, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d,
        0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc,
        0xe0, 0x36, 0xf9,
    ],
    [
        0x02, 0xe4, 0x93, 0xdb, 0xf1, 0xc1, 0x0d, 0x80, 0xf3, 0x58, 0x1e, 0x49, 0x04, 0x93, 0x0b,
        0x14, 0x04, 0xcc, 0x6c, 0x13, 0x90, 0x0e, 0xe0, 0x75, 0x84, 0x74, 0xfa, 0x94, 0xab, 0xe8,
        0xc4, 0xcd, 0x13,
    ],
    [
        0x02, 0x2f, 0x8b, 0xde, 0x4d, 0x1a, 0x07, 0x20, 0x93, 0x55, 0xb4, 0xa7, 0x25, 0x0a, 0x5c,
        0x51, 0x28, 0xe8, 0x8b, 0x84, 0xbd, 0xdc, 0x61, 0x9a, 0xb7, 0xcb, 0xa8, 0xd5, 0x69, 0xb2,
        0x40, 0xef, 0xe4,
    ],
    [
        0x03, 0xff, 0xf9, 0x7b, 0xd5, 0x75, 0x5e, 0xee, 0xa4, 0x20, 0x45, 0x3a, 0x14, 0x35, 0x52,
        0x35, 0xd3, 0x82, 0xf6, 0x47, 0x2f, 0x85, 0x68, 0xa1, 0x8b, 0x2f, 0x05, 0x7a, 0x14, 0x60,
        0x29, 0x75, 0x56,
    ],
    [
        0x02, 0x5c, 0xbd, 0xf0, 0x64, 0x6e, 0x5d, 0xb4, 0xea, 0xa3, 0x98, 0xf3, 0x65, 0xf2, 0xea,
        0x7a, 0x0e, 0x3d, 0x41, 0x9b, 0x7e, 0x03, 0x30, 0xe3, 0x9c, 0xe9, 0x2b, 0xdd, 0xed, 0xca,
        0xc4, 0xf9, 0xbc,
    ],
];

/// Returns the deterministic 5-of-7 manager set for isolated local regtest.
pub fn local_regtest_manager_set() -> ManagerSet {
    ManagerSet {
        m: LOCAL_REGTEST_MANAGER_SET_M,
        n: LOCAL_REGTEST_MANAGER_SET_N,
        pubkeys: LOCAL_REGTEST_MANAGER_SET_PUBKEYS.to_vec(),
    }
}

/// Wormhole signed VAA header fields extracted for relay use.
#[derive(Debug, Clone)]
pub struct VaaHeader {
    pub version: u8,
    pub guardian_set_index: u32,
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
    pub payload: Vec<u8>, // raw payload bytes (starts with "UTX0" for unlock VAAs)
}

/// Parse a Wormhole VAA into its header + payload.
///
/// VAA layout (big-endian, matching `wormhole/sdk/vaa/structs.go`):
///   version(1) + guardian_set_index(4 BE) + sig_count(1)
///   + sig_count * (index(1) + 65B sig)
///   + timestamp(4 BE) + nonce(4 BE) + emitter_chain(2 BE)
///   + emitter_address(32) + sequence(8 BE) + consistency_level(1)
///   + payload[]
pub fn parse_vaa(bytes: &[u8]) -> Result<VaaHeader> {
    if bytes.len() < 6 {
        bail!("VAA too short: {} bytes", bytes.len());
    }
    let version = bytes[0];
    let guardian_set_index = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
    let sig_count = bytes[5] as usize;
    let mut off = 6 + sig_count * (1 + 65);
    if bytes.len() < off + 4 + 4 + 2 + 32 + 8 + 1 {
        bail!("VAA body too short for header fields");
    }
    let _timestamp = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
    off += 4;
    let _nonce = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
    off += 4;
    let emitter_chain = u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap());
    off += 2;
    let mut emitter_address = [0u8; 32];
    emitter_address.copy_from_slice(&bytes[off..off + 32]);
    off += 32;
    let sequence = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
    off += 8;
    let _consistency_level = bytes[off];
    off += 1;
    let payload = bytes[off..].to_vec();
    Ok(VaaHeader {
        version,
        guardian_set_index,
        emitter_chain,
        emitter_address,
        sequence,
        payload,
    })
}

/// One signer's aggregated signatures across all inputs of a UTXO unlock tx.
#[derive(Debug, Clone, Default)]
pub struct SignerSignatures {
    pub signer_index: u8,
    /// One DER-encoded signature (with appended sighash type byte) per tx
    /// input, in input order.
    pub input_signatures: Vec<Vec<u8>>,
}

/// Aggregated manager-service response for a UTXO unlock VAA.
///
/// **Important:** the manager-service response does NOT carry the signed VAA
/// bytes — fetch those separately with [`fetch_signed_vaa`]. The `vaa_hash`
/// here is the guardian's `keccak256(keccak256(vaa_body))` signing digest and
/// MUST be matched against the separately-fetched signed VAA via
/// [`vaa_hash_matches`] before trusting any signature. Never treat
/// `is_complete` as sufficient; verify every signature locally with
/// [`verify_manager_signature`].
#[derive(Debug, Clone)]
pub struct ManagerSignatures {
    /// Guardian-reported M-of-N collection flag. **Advisory only** — the relay
    /// must still verify every signature against its per-input SIGHASH_ALL.
    pub is_complete: bool,
    /// `keccak256(keccak256(vaa_body))` (32 bytes), hex in the JSON `vaaHash`.
    /// Join key against the separately-fetched signed VAA.
    pub vaa_hash: [u8; 32],
    /// `"{chain}/{emitter_hex}/{sequence}"` from `vaaId`.
    pub vaa_id: String,
    /// Destination Wormhole chain ID (Dogecoin = 65) from `destinationChain`.
    pub destination_chain: u16,
    /// Delegated manager set index from `managerSetIndex`.
    pub manager_set_index: u32,
    /// Required signature threshold M from `required`.
    pub required: u32,
    /// Total signers N from `total`.
    pub total: u32,
    /// Per-signer signature aggregation.
    pub signatures: Vec<SignerSignatures>,
}

/// JSON shape returned by `GET /v1/manager/signed_vaa/{chain}/{emitter}/{seq}`.
///
/// Mirrors the protobuf `GetSignedManagerTransactionResponse`
/// (`proto/publicrpc/v1/publicrpc.proto:265-282`): camelCase field names, the
/// `signatures` array holds base64-encoded DER+hashtype bytes (protobuf
/// `bytes` JSON mapping), and there is **no** `vaaBytes` field — the signed
/// VAA must be fetched separately. `complete` and `inputSignatures` are
/// tolerated as backwards-compat aliases.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ManagerSignaturesJson {
    #[serde(default, alias = "complete")]
    is_complete: Option<bool>,
    #[serde(default)]
    vaa_hash: Option<String>,
    #[serde(default)]
    vaa_id: Option<String>,
    #[serde(default)]
    destination_chain: Option<u32>,
    #[serde(default)]
    manager_set_index: Option<u32>,
    #[serde(default)]
    required: Option<u32>,
    #[serde(default)]
    total: Option<u32>,
    #[serde(default)]
    signatures: Vec<SignerSignaturesJson>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignerSignaturesJson {
    #[serde(default)]
    signer_index: Option<u32>,
    /// Base64-encoded DER+hashtype signatures, one per tx input.
    /// `inputSignatures` is accepted as a legacy alias.
    #[serde(default, alias = "inputSignatures")]
    signatures: Vec<String>,
}

/// Fetch the aggregated manager signatures for a UTXO unlock VAA.
///
/// `base_url` is the guardian API base (e.g. `https://wormhole-v2-testnet-api\
/// .crosschainibc.com`). `chain` is the emitter Wormhole chain ID, `emitter`
/// is the 32-byte emitter address, and `sequence` is the VAA sequence.
///
/// Hits the official route
/// `GET /v1/manager/signed_vaa/{chain}/{emitter}/{sequence}` (path params).
/// The signed VAA bytes are NOT part of this response — fetch them with
/// [`fetch_signed_vaa`] and join via [`vaa_hash_matches`].
pub async fn fetch_manager_signatures(
    client: &reqwest::Client,
    base_url: &str,
    chain: u16,
    emitter: &[u8; 32],
    sequence: u64,
) -> Result<ManagerSignatures> {
    let emitter_hex = hex::encode(emitter);
    let url = format!(
        "{}/v1/manager/signed_vaa/{chain}/{emitter_hex}/{sequence}",
        base_url.trim_end_matches('/'),
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("manager API request failed: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.context("manager API: read body")?;
    if !status.is_success() {
        bail!("manager API {url} returned {status}: {body}");
    }
    parse_manager_signatures(&body)
}

/// Fetch the raw signed VAA bytes from the dedicated endpoint
/// `GET /v1/signed_vaa/{chain}/{emitter}/{sequence}`.
///
/// The manager-service response ([`fetch_manager_signatures`]) does NOT carry
/// the VAA bytes; the relay must fetch them here and join the two responses by
/// verifying the guardian-reported `vaaHash` against the VAA signing digest
/// ([`vaa_hash_matches`]).
///
/// Response shape (protobuf `GetSignedVAAResponse`, base64 JSON mapping):
/// `{"vaaBytes": "<base64>"}`.
pub async fn fetch_signed_vaa(
    client: &reqwest::Client,
    base_url: &str,
    chain: u16,
    emitter: &[u8; 32],
    sequence: u64,
) -> Result<Vec<u8>> {
    let emitter_hex = hex::encode(emitter);
    let url = format!(
        "{}/v1/signed_vaa/{chain}/{emitter_hex}/{sequence}",
        base_url.trim_end_matches('/'),
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("signed_vaa API request failed: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.context("signed_vaa API: read body")?;
    if !status.is_success() {
        bail!("signed_vaa API {url} returned {status}: {body}");
    }
    let json: SignedVaaJson =
        serde_json::from_str(&body).map_err(|e| anyhow!("signed_vaa JSON decode: {e}"))?;
    let b64 = json
        .vaa_bytes
        .ok_or_else(|| anyhow!("signed_vaa response missing vaaBytes"))?;
    b64_decode(&b64)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedVaaJson {
    vaa_bytes: Option<String>,
}

/// Parse the manager-service JSON response. Exposed for testing.
pub fn parse_manager_signatures(body: &str) -> Result<ManagerSignatures> {
    let json: ManagerSignaturesJson =
        serde_json::from_str(body).map_err(|e| anyhow!("manager API JSON decode: {e}"))?;

    let vaa_hash_hex = json
        .vaa_hash
        .as_deref()
        .ok_or_else(|| anyhow!("manager API response missing vaaHash"))?;
    let vaa_hash = hex_decode_fixed::<32>(vaa_hash_hex.trim_start_matches("0x"))?;

    let mut signatures = Vec::with_capacity(json.signatures.len());
    for s in json.signatures {
        let signer_index = s.signer_index.unwrap_or(0) as u8;
        let mut input_signatures = Vec::with_capacity(s.signatures.len());
        for b64 in s.signatures {
            input_signatures.push(b64_decode(&b64)?);
        }
        signatures.push(SignerSignatures {
            signer_index,
            input_signatures,
        });
    }

    Ok(ManagerSignatures {
        is_complete: json.is_complete.unwrap_or(false),
        vaa_hash,
        vaa_id: json.vaa_id.unwrap_or_default(),
        destination_chain: json.destination_chain.unwrap_or(0) as u16,
        manager_set_index: json.manager_set_index.unwrap_or(0),
        required: json.required.unwrap_or(0),
        total: json.total.unwrap_or(0),
        signatures,
    })
}

/// Slice the VAA body (everything after the signature header) from a signed
/// VAA. Layout: version(1) + guardian_set_index(4) + sig_count(1) +
/// sig_count*(index(1)+65) + body.
pub fn vaa_body(signed_vaa: &[u8]) -> Result<&[u8]> {
    if signed_vaa.len() < 6 {
        bail!("VAA too short: {} bytes", signed_vaa.len());
    }
    let sig_count = signed_vaa[5] as usize;
    let body_off = 6 + sig_count * (1 + 65);
    if signed_vaa.len() < body_off {
        bail!("VAA truncated before body");
    }
    Ok(&signed_vaa[body_off..])
}

/// Compute the guardian signing digest of a signed VAA's body:
/// `keccak256(keccak256(body))`. This is exactly the value the manager service
/// reports as `vaaHash` (`wormhole/sdk/vaa/structs.go:586` `SigningDigest`,
/// set at `wormhole/node/pkg/manager/manager.go:941`).
pub fn vaa_signing_digest(signed_vaa: &[u8]) -> Result<[u8; 32]> {
    use sha3::{Digest, Keccak256};
    let body = vaa_body(signed_vaa)?;
    let mut h1 = Keccak256::new();
    h1.update(body);
    let first = h1.finalize();
    let mut h2 = Keccak256::new();
    h2.update(first);
    let second = h2.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    Ok(out)
}

/// Join check: the manager-reported `vaaHash` must equal the signing digest of
/// the separately-fetched signed VAA. Returns `true` on match. This binds the
/// signature set to the exact VAA the relay will execute.
pub fn vaa_hash_matches(signed_vaa: &[u8], manager_vaa_hash: &[u8; 32]) -> Result<bool> {
    let computed = vaa_signing_digest(signed_vaa)?;
    Ok(&computed == manager_vaa_hash)
}

fn hex_decode_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("hex decode failed for {s:?}: {e}"))?;
    if bytes.len() != N {
        bail!("expected {N} hex bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow!("base64 decode failed for {s:?}: {e}"))
}

/// Verify a DER+hashtype manager signature against a SIGHASH_ALL digest and
/// compressed pubkey. Other hash types are rejected before ECDSA verification.
pub fn verify_manager_signature(
    pubkey_compressed: &[u8; 33],
    sighash: &[u8; 32],
    der_with_hashtype: &[u8],
) -> Result<bool> {
    let Some((&hash_type, der)) = der_with_hashtype.split_last() else {
        bail!("empty signature");
    };
    if hash_type != SIGHASH_ALL as u8 {
        bail!("manager signature hash type {hash_type:#04x} is not SIGHASH_ALL (0x01)");
    }
    let secp = secp256k1::Secp256k1::verification_only();
    let pk = secp256k1::PublicKey::from_slice(pubkey_compressed)
        .map_err(|e| anyhow!("invalid pubkey: {e}"))?;
    let msg = secp256k1::Message::from_digest(*sighash);
    let sig = secp256k1::ecdsa::Signature::from_der(der)
        .map_err(|e| anyhow!("invalid DER signature: {e}"))?;
    Ok(secp.verify_ecdsa(msg, &sig, &pk).is_ok())
}

/// Canonical identifier for one registered VAA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaaKey {
    pub emitter_chain: u16,
    pub emitter_address: [u8; 32],
    pub sequence: u64,
}

/// Exact registration accepted by the local-regtest service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWithdrawalRegistration {
    pub key: VaaKey,
    pub payload: Vec<u8>,
}

/// Fully materialized local response, built once at registration time.
#[derive(Debug, Clone)]
pub struct LocalSignedWithdrawal {
    pub signed_vaa: Vec<u8>,
    pub manager_signatures: ManagerSignatures,
}

/// Registration outcome. Re-registering identical bytes is idempotent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationOutcome {
    Inserted,
    AlreadyRegistered,
}

/// Deterministic in-memory manager/VAA state for isolated Dogecoin regtest.
#[derive(Debug, Default)]
pub struct LocalManagerService {
    withdrawals: HashMap<VaaKey, (Vec<u8>, LocalSignedWithdrawal)>,
}

impl LocalManagerService {
    pub fn register(
        &mut self,
        registration: LocalWithdrawalRegistration,
    ) -> Result<RegistrationOutcome> {
        if let Some((payload, _)) = self.withdrawals.get(&registration.key) {
            if payload == &registration.payload {
                return Ok(RegistrationOutcome::AlreadyRegistered);
            }
            bail!(
                "conflicting payload already registered for {}",
                vaa_id(registration.key)
            );
        }

        let signed = build_local_signed_withdrawal(&registration)?;
        self.withdrawals
            .insert(registration.key, (registration.payload, signed));
        Ok(RegistrationOutcome::Inserted)
    }

    pub fn get(&self, key: &VaaKey) -> Option<&LocalSignedWithdrawal> {
        self.withdrawals.get(key).map(|(_, signed)| signed)
    }
}

/// Synthesize the unsigned transaction and its quorum signatures from an exact
/// UTX0 payload. This is local infrastructure, not guardian emulation.
pub fn build_local_signed_withdrawal(
    registration: &LocalWithdrawalRegistration,
) -> Result<LocalSignedWithdrawal> {
    let payload = Utx0UnlockPayload::parse(&registration.payload)
        .context("registration payload is not a canonical UTX0 payload")?;
    if payload.delegated_manager_set_index != 0 {
        bail!(
            "local regtest only supports delegated manager set index 0, got {}",
            payload.delegated_manager_set_index
        );
    }
    if payload.destination_chain != chain_id::DOGECOIN {
        bail!(
            "local regtest manager only signs Dogecoin destination chain {}, got {}",
            chain_id::DOGECOIN,
            payload.destination_chain
        );
    }

    let manager_set = local_regtest_manager_set();
    let redeem_scripts = payload
        .inputs
        .iter()
        .map(|input| {
            build_redeem_script(
                registration.key.emitter_chain,
                &registration.key.emitter_address,
                &input.original_recipient_address,
                manager_set.m,
                &manager_set.pubkeys,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let tx = UnsignedTransaction::from_utx0(&payload, redeem_scripts)?;
    let sighashes = (0..tx.input_count())
        .map(|input_index| tx.sighash_all(input_index))
        .collect::<Result<Vec<_>>>()?;

    let secp = Secp256k1::signing_only();
    let signatures = LOCAL_REGTEST_MANAGER_PRIVATE_KEYS
        .iter()
        .take(manager_set.m as usize)
        .enumerate()
        .map(|(signer_index, secret_bytes)| -> Result<SignerSignatures> {
            let secret = SecretKey::from_byte_array(*secret_bytes)
                .map_err(|e| anyhow!("invalid local manager secret {signer_index}: {e}"))?;
            let input_signatures = sighashes
                .iter()
                .map(|sighash| {
                    let message = Message::from_digest(*sighash);
                    let signature = secp.sign_ecdsa(message, &secret);
                    let mut encoded = signature.serialize_der().to_vec();
                    encoded.push(SIGHASH_ALL as u8);
                    encoded
                })
                .collect();
            Ok(SignerSignatures {
                signer_index: signer_index as u8,
                input_signatures,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let signed_vaa = synthesize_local_vaa(registration);
    let vaa_hash = vaa_signing_digest(&signed_vaa)?;
    Ok(LocalSignedWithdrawal {
        signed_vaa,
        manager_signatures: ManagerSignatures {
            is_complete: true,
            vaa_hash,
            vaa_id: vaa_id(registration.key),
            destination_chain: payload.destination_chain,
            manager_set_index: payload.delegated_manager_set_index,
            required: manager_set.m as u32,
            total: manager_set.n as u32,
            signatures,
        },
    })
}

/// JSON response for the existing manager-signature endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagerSignaturesResponse<'a> {
    pub is_complete: bool,
    pub vaa_hash: String,
    pub vaa_id: &'a str,
    pub destination_chain: u16,
    pub manager_set_index: u32,
    pub required: u32,
    pub total: u32,
    pub signatures: Vec<SignerSignaturesResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerSignaturesResponse {
    pub signer_index: u8,
    pub signatures: Vec<String>,
}

impl ManagerSignatures {
    pub fn response(&self) -> ManagerSignaturesResponse<'_> {
        ManagerSignaturesResponse {
            is_complete: self.is_complete,
            vaa_hash: hex::encode(self.vaa_hash),
            vaa_id: &self.vaa_id,
            destination_chain: self.destination_chain,
            manager_set_index: self.manager_set_index,
            required: self.required,
            total: self.total,
            signatures: self
                .signatures
                .iter()
                .map(|signer| SignerSignaturesResponse {
                    signer_index: signer.signer_index,
                    signatures: signer
                        .input_signatures
                        .iter()
                        .map(|signature| general_purpose::STANDARD.encode(signature))
                        .collect(),
                })
                .collect(),
        }
    }
}

/// JSON response for the existing signed-VAA endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedVaaResponse {
    pub vaa_bytes: String,
}

impl SignedVaaResponse {
    pub fn new(signed_vaa: &[u8]) -> Self {
        Self {
            vaa_bytes: general_purpose::STANDARD.encode(signed_vaa),
        }
    }
}

fn synthesize_local_vaa(registration: &LocalWithdrawalRegistration) -> Vec<u8> {
    let mut vaa = Vec::with_capacity(57 + registration.payload.len());
    vaa.push(1); // VAA version
    vaa.extend_from_slice(&0u32.to_be_bytes()); // local guardian set index
    vaa.push(0); // no guardian signatures: local noop-shim has no guardian network
    vaa.extend_from_slice(&0u32.to_be_bytes()); // deterministic timestamp
    vaa.extend_from_slice(&0u32.to_be_bytes()); // deterministic nonce
    vaa.extend_from_slice(&registration.key.emitter_chain.to_be_bytes());
    vaa.extend_from_slice(&registration.key.emitter_address);
    vaa.extend_from_slice(&registration.key.sequence.to_be_bytes());
    vaa.push(0); // consistency level
    vaa.extend_from_slice(&registration.payload);
    vaa
}

fn vaa_id(key: VaaKey) -> String {
    format!(
        "{}/{}/{}",
        key.emitter_chain,
        hex::encode(key.emitter_address),
        key.sequence
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::PublicKey;

    #[test]
    fn manager_set_round_trip() {
        let ms = local_regtest_manager_set();
        assert_eq!(ms.m, 5);
        assert_eq!(ms.n, 7);
        assert_eq!(ms.pubkeys.len(), 7);
        let bytes = ms.serialize();
        let parsed = ManagerSet::parse(&bytes).unwrap();
        assert_eq!(parsed, ms);
    }

    #[test]
    fn parse_vaa_extracts_utx0_payload() {
        // Build a minimal VAA with one guardian sig and a UTX0 payload.
        let payload = Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 1,
            inputs: vec![],
            outputs: vec![],
        };
        let payload_bytes = payload.serialize().unwrap();

        let mut vaa = Vec::new();
        vaa.push(1u8); // version
        vaa.extend_from_slice(&0u32.to_be_bytes()); // guardian set index
        vaa.push(1u8); // sig count
        vaa.push(0u8); // guardian index
        vaa.extend_from_slice(&[0u8; 65]); // dummy sig
        vaa.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        vaa.extend_from_slice(&0u32.to_be_bytes()); // nonce
        vaa.extend_from_slice(&1u16.to_be_bytes()); // emitter chain (Solana)
        vaa.extend_from_slice(&[0xaa; 32]); // emitter address
        vaa.extend_from_slice(&42u64.to_be_bytes()); // sequence
        vaa.push(32u8); // consistency level
        vaa.extend_from_slice(&payload_bytes);

        let header = parse_vaa(&vaa).unwrap();
        assert_eq!(header.emitter_chain, 1);
        assert_eq!(header.sequence, 42);
        assert_eq!(header.emitter_address, [0xaa; 32]);
        let p = Utx0UnlockPayload::parse(&header.payload).unwrap();
        assert_eq!(p.destination_chain, 65);
        assert_eq!(p.delegated_manager_set_index, 1);
    }

    #[test]
    fn parse_manager_signatures_decodes_base64_and_metadata() {
        use base64::{engine::general_purpose, Engine as _};

        // A dummy DER + trailing SIGHASH_ALL (0x01) byte; the relay decodes
        // before verifying, so the exact bytes need not be a valid signature.
        let der_with_hashtype: [u8; 5] = [0x30, 0x02, 0x01, 0x01, 0x01];
        let b64_sig = general_purpose::STANDARD.encode(der_with_hashtype);

        let emitter = [0u8; 32];
        let vaa_hash = [0xaa; 32];
        let body = format!(
            "{{\"vaaHash\":\"{}\",\"vaaId\":\"1/{}/7\",\"destinationChain\":65,\
             \"managerSetIndex\":3,\"required\":5,\"total\":7,\"isComplete\":true,\
             \"signatures\":[{{\"signerIndex\":2,\"signatures\":[\"{}\"]}}]}}",
            hex::encode(vaa_hash),
            hex::encode(emitter),
            b64_sig,
        );
        let ms = parse_manager_signatures(&body).unwrap();
        assert!(ms.is_complete);
        assert_eq!(ms.vaa_hash, vaa_hash);
        assert_eq!(ms.vaa_id, format!("1/{}/7", hex::encode(emitter)));
        assert_eq!(ms.destination_chain, 65);
        assert_eq!(ms.manager_set_index, 3);
        assert_eq!(ms.required, 5);
        assert_eq!(ms.total, 7);
        assert_eq!(ms.signatures.len(), 1);
        assert_eq!(ms.signatures[0].signer_index, 2);
        assert_eq!(
            ms.signatures[0].input_signatures,
            vec![der_with_hashtype.to_vec()]
        );
    }

    #[test]
    fn vaa_signing_digest_is_double_keccak_of_body() {
        use sha3::{Digest, Keccak256};

        // Signed VAA with zero guardian signatures and a known body.
        let body = [0x42u8; 10];
        let mut vaa = vec![1u8]; // version
        vaa.extend_from_slice(&0u32.to_be_bytes()); // guardian set index
        vaa.push(0u8); // sig count = 0
        vaa.extend_from_slice(&body);

        let mut h1 = Keccak256::new();
        h1.update(&body);
        let first = h1.finalize();
        let mut h2 = Keccak256::new();
        h2.update(first);
        let expected = h2.finalize();

        let digest = vaa_signing_digest(&vaa).unwrap();
        assert_eq!(&digest[..], &expected[..]);
        assert!(vaa_hash_matches(&vaa, &digest).unwrap());
    }

    fn local_registration(payload: &Utx0UnlockPayload) -> LocalWithdrawalRegistration {
        LocalWithdrawalRegistration {
            key: VaaKey {
                emitter_chain: 1,
                emitter_address: [0x42; 32],
                sequence: 9,
            },
            payload: payload.serialize().unwrap(),
        }
    }

    fn signing_payload() -> Utx0UnlockPayload {
        use super::super::utx0::{Utx0Input, Utx0Output, UtxoAddressType};

        Utx0UnlockPayload {
            destination_chain: 65,
            delegated_manager_set_index: 0,
            inputs: vec![
                Utx0Input {
                    original_recipient_address: [0x11; 32],
                    transaction_id: [0x22; 32],
                    vout: 0,
                },
                Utx0Input {
                    original_recipient_address: [0x33; 32],
                    transaction_id: [0x44; 32],
                    vout: 1,
                },
            ],
            outputs: vec![Utx0Output {
                amount: 100_000_000,
                address_type: UtxoAddressType::P2pkh,
                address: vec![0x55; 20],
            }],
        }
    }

    #[test]
    fn local_fixture_pubkeys_match_private_keys() {
        let secp = Secp256k1::signing_only();
        for (secret_bytes, expected) in LOCAL_REGTEST_MANAGER_PRIVATE_KEYS
            .iter()
            .zip(LOCAL_REGTEST_MANAGER_SET_PUBKEYS)
        {
            let secret = SecretKey::from_byte_array(*secret_bytes).unwrap();
            assert_eq!(
                PublicKey::from_secret_key(&secp, &secret).serialize(),
                expected
            );
        }
    }

    #[test]
    fn local_service_vaa_and_all_manager_signatures_verify() {
        let registration = local_registration(&signing_payload());
        let signed = build_local_signed_withdrawal(&registration).unwrap();
        let parsed = parse_vaa(&signed.signed_vaa).unwrap();
        assert_eq!(parsed.emitter_chain, registration.key.emitter_chain);
        assert_eq!(parsed.emitter_address, registration.key.emitter_address);
        assert_eq!(parsed.sequence, registration.key.sequence);
        assert_eq!(parsed.payload, registration.payload);
        assert!(vaa_hash_matches(&signed.signed_vaa, &signed.manager_signatures.vaa_hash).unwrap());

        let payload = Utx0UnlockPayload::parse(&parsed.payload).unwrap();
        let manager_set = local_regtest_manager_set();
        let redeem_scripts = payload
            .inputs
            .iter()
            .map(|input| {
                build_redeem_script(
                    parsed.emitter_chain,
                    &parsed.emitter_address,
                    &input.original_recipient_address,
                    manager_set.m,
                    &manager_set.pubkeys,
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let tx = UnsignedTransaction::from_utx0(&payload, redeem_scripts).unwrap();
        assert_eq!(
            signed.manager_signatures.signatures.len(),
            manager_set.m as usize
        );
        for signer in &signed.manager_signatures.signatures {
            assert_eq!(signer.input_signatures.len(), tx.input_count());
            for (input_index, signature) in signer.input_signatures.iter().enumerate() {
                assert_eq!(signature.last(), Some(&(SIGHASH_ALL as u8)));
                assert!(verify_manager_signature(
                    &manager_set.pubkeys[signer.signer_index as usize],
                    &tx.sighash_all(input_index).unwrap(),
                    signature,
                )
                .unwrap());
            }
        }
    }

    #[test]
    fn local_registration_is_idempotent_but_rejects_conflicts() {
        let registration = local_registration(&signing_payload());
        let mut service = LocalManagerService::default();
        assert_eq!(
            service.register(registration.clone()).unwrap(),
            RegistrationOutcome::Inserted
        );
        assert_eq!(
            service.register(registration.clone()).unwrap(),
            RegistrationOutcome::AlreadyRegistered
        );

        let mut conflicting = registration;
        let last = conflicting.payload.len() - 1;
        conflicting.payload[last] ^= 1;
        let error = service.register(conflicting).unwrap_err();
        assert!(error.to_string().contains("conflicting payload"));
    }

    #[test]
    fn invalid_first_registration_does_not_reserve_key() {
        let payload = signing_payload();
        let mut invalid = local_registration(&payload);
        invalid.payload.pop();
        let valid = local_registration(&payload);
        let key = valid.key;

        let mut service = LocalManagerService::default();
        assert!(service.register(invalid).is_err());
        assert_eq!(
            service.register(valid).unwrap(),
            RegistrationOutcome::Inserted
        );
        assert!(service.get(&key).is_some());
    }
}
