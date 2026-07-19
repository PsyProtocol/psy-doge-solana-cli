//! Runtime network profiles for the production-facing CLI.
//!
//! User-facing selection is only `--network localhost|devnet`. Dogecoin
//! regtest/testnet address encoding is derived from that choice and is never a
//! separate public flag.

use anyhow::{bail, Context, Result};
use std::net::IpAddr;

use clap::ValueEnum;

/// Official Wormhole Testnet Core Bridge on Solana devnet.
pub const OFFICIAL_WORMHOLE_CORE: &str = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";
/// Official Wormhole Post Message Shim on Solana devnet.
pub const OFFICIAL_WORMHOLE_SHIM: &str = "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";
/// Local-regtest noop shim used in place of Wormhole Core/Shim.
pub const LOCAL_NOOP_SHIM: &str = "FwDChsHWLwbhTiYQ4Sum5mjVWswECi9cmrA11GUFUuxi";

pub const LOCAL_SOLANA_RPC: &str = "http://127.0.0.1:8899";
pub const DEVNET_SOLANA_RPC: &str = "https://api.devnet.solana.com";
pub const LOCAL_ELECTRS_URL: &str = "http://127.0.0.1:3002";
pub const QED_TESTNET_ELECTRS_URL: &str = "https://doge-electrs-testnet-demo.qed.me";
pub const LOCAL_MANAGER_SERVICE_URL: &str = "http://127.0.0.1:7071";

/// User-facing runtime network selected by global `--network`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum RuntimeNetwork {
    /// Dogecoin regtest + local Solana validator + local Manager set 0 + noop Wormhole.
    #[default]
    Localhost,
    /// Dogecoin testnet + Solana devnet + QED Electrs + official Wormhole + Manager set 1.
    Devnet,
}

impl RuntimeNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Localhost => "localhost",
            Self::Devnet => "devnet",
        }
    }

    pub fn is_localhost(self) -> bool {
        matches!(self, Self::Localhost)
    }
    pub fn validate_remote_url(self, label: &str, value: &str) -> Result<()> {
        if self.is_localhost() {
            return Ok(());
        }
        let url = reqwest::Url::parse(value)
            .with_context(|| format!("invalid {label} URL '{value}'"))?;
        if !matches!(url.scheme(), "http" | "https") {
            bail!("{label} must use http or https on --network devnet");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("{label} URL has no host"))?;
        if host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| match ip {
                IpAddr::V4(ip) => {
                    ip.is_loopback()
                        || ip.is_unspecified()
                        || ip.is_private()
                        || ip.is_link_local()
                }
                IpAddr::V6(ip) => {
                    ip.is_loopback()
                        || ip.is_unspecified()
                        || (ip.segments()[0] & 0xfe00) == 0xfc00
                        || (ip.segments()[0] & 0xffc0) == 0xfe80
                }
            })
        {
            bail!("{label} must be externally operated on --network devnet; local endpoint '{host}' is forbidden");
        }
        Ok(())
    }

    pub fn validate_manager_set(self, index: u32) -> Result<()> {
        if matches!(self, Self::Devnet) && index != 1 {
            bail!("--network devnet requires official Dogecoin Manager set index 1; got {index}");
        }
        Ok(())
    }

    pub fn validate_wormhole_programs(self, core: &str, shim: &str) -> Result<()> {
        if matches!(self, Self::Devnet)
            && (core != OFFICIAL_WORMHOLE_CORE || shim != OFFICIAL_WORMHOLE_SHIM)
        {
            bail!(
                "--network devnet requires official Wormhole Core {} and shim {}; got Core {} and shim {}",
                OFFICIAL_WORMHOLE_CORE,
                OFFICIAL_WORMHOLE_SHIM,
                core,
                shim,
            );
        }
        Ok(())
    }


    pub fn defaults(self) -> NetworkDefaults {
        match self {
            Self::Localhost => NetworkDefaults {
                doge_network: DogeNetwork::Regtest,
                solana_rpc_url: LOCAL_SOLANA_RPC,
                electrs_url: LOCAL_ELECTRS_URL,
                manager_service_url: Some(LOCAL_MANAGER_SERVICE_URL),
                manager_set_index: 0,
                wormhole_core_program: LOCAL_NOOP_SHIM,
                wormhole_shim_program: LOCAL_NOOP_SHIM,
            },
            Self::Devnet => NetworkDefaults {
                doge_network: DogeNetwork::Testnet,
                solana_rpc_url: DEVNET_SOLANA_RPC,
                electrs_url: QED_TESTNET_ELECTRS_URL,
                // External Manager endpoint must be supplied by the operator.
                manager_service_url: None,
                manager_set_index: 1,
                wormhole_core_program: OFFICIAL_WORMHOLE_CORE,
                wormhole_shim_program: OFFICIAL_WORMHOLE_SHIM,
            },
        }
    }
}

/// Profile defaults applied centrally before subcommand dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkDefaults {
    pub doge_network: DogeNetwork,
    pub solana_rpc_url: &'static str,
    pub electrs_url: &'static str,
    pub manager_service_url: Option<&'static str>,
    pub manager_set_index: u32,
    pub wormhole_core_program: &'static str,
    pub wormhole_shim_program: &'static str,
}

/// Dogecoin wire/address network derived from [`RuntimeNetwork`].
///
/// Not exposed as a user-facing CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum DogeNetwork {
    #[default]
    Regtest,
    Testnet,
}

impl DogeNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet => "testnet",
        }
    }

    pub fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            Self::Regtest => bitcoin::Network::Regtest,
            Self::Testnet => bitcoin::Network::Testnet,
        }
    }

    pub fn p2pkh_version(self) -> u8 {
        match self {
            Self::Regtest => 0x6f,
            Self::Testnet => 0x71,
        }
    }

    pub fn wif_version(self) -> u8 {
        match self {
            Self::Regtest => 0xef,
            Self::Testnet => 0xf1,
        }
    }

    pub fn encode_address(self, address_type: u32, payload: [u8; 20]) -> anyhow::Result<String> {
        let version = match (self, address_type) {
            (_, 0) => self.p2pkh_version(),
            (_, 1) => 0xc4,
            (_, other) => anyhow::bail!("unsupported Dogecoin address type {other}"),
        };
        let mut bytes = Vec::with_capacity(21);
        bytes.push(version);
        bytes.extend_from_slice(&payload);
        Ok(bs58::encode(bytes).with_check().into_string())
    }

    pub fn validate_wif(self, wif: &str) -> anyhow::Result<()> {
        let decoded = bs58::decode(wif).with_check(None).into_vec()?;
        if decoded.len() != 33 && decoded.len() != 34 {
            anyhow::bail!(
                "Dogecoin WIF payload must be 33 or 34 bytes, got {}",
                decoded.len()
            );
        }
        if decoded[0] != self.wif_version() {
            anyhow::bail!(
                "WIF version 0x{:02x} does not match {} (expected 0x{:02x})",
                decoded[0],
                self.as_str(),
                self.wif_version(),
            );
        }
        if decoded.len() == 34 && decoded[33] != 1 {
            anyhow::bail!("compressed Dogecoin WIF is missing the 0x01 marker");
        }
        Ok(())
    }
}

/// Fill an optional string override from the active runtime profile.
pub fn fill_string(slot: &mut Option<String>, default: &str) {
    if slot.is_none() {
        *slot = Some(default.to_owned());
    }
}

/// Fill an optional string override from an optional profile default.
pub fn fill_string_optional(slot: &mut Option<String>, default: Option<&str>) {
    if slot.is_none() {
        if let Some(value) = default {
            *slot = Some(value.to_owned());
        }
    }
}

/// Fill an optional numeric override from the active runtime profile.
pub fn fill_u32(slot: &mut Option<u32>, default: u32) {
    if slot.is_none() {
        *slot = Some(default);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_rejects_local_endpoints_and_noncanonical_ids() {
        let devnet = RuntimeNetwork::Devnet;
        assert!(devnet
            .validate_remote_url("Solana RPC", "http://127.0.0.1:8899")
            .is_err());
        assert!(devnet
            .validate_remote_url("Manager service", "http://localhost:7071")
            .is_err());
        assert!(devnet
            .validate_remote_url("Manager service", "http://10.0.0.8:7071")
            .is_err());
        assert!(devnet
            .validate_remote_url("Electrs", QED_TESTNET_ELECTRS_URL)
            .is_ok());
        assert!(devnet.validate_manager_set(0).is_err());
        assert!(devnet.validate_manager_set(1).is_ok());
        assert!(devnet
            .validate_wormhole_programs(LOCAL_NOOP_SHIM, LOCAL_NOOP_SHIM)
            .is_err());
        assert!(devnet
            .validate_wormhole_programs(OFFICIAL_WORMHOLE_CORE, OFFICIAL_WORMHOLE_SHIM)
            .is_ok());
    }

    #[test]
    fn localhost_allows_explicit_local_overrides() {
        let localhost = RuntimeNetwork::Localhost;
        assert!(localhost
            .validate_remote_url("Solana RPC", LOCAL_SOLANA_RPC)
            .is_ok());
        assert!(localhost.validate_manager_set(0).is_ok());
        assert!(localhost
            .validate_wormhole_programs(LOCAL_NOOP_SHIM, LOCAL_NOOP_SHIM)
            .is_ok());
    }
}
