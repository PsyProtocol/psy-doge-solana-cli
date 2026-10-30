use std::net::SocketAddr;

pub(super) fn validate_listen_address(address: SocketAddr) -> anyhow::Result<()> {
    // Deterministic regtest signing keys must stay behind a loopback interface.
    anyhow::ensure!(address.ip().is_loopback(), "local Manager service requires a loopback listen address");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_public_signing_interfaces() {
        for address in ["0.0.0.0:7071", "[::]:7071", "192.0.2.1:7071"] {
            assert!(validate_listen_address(address.parse().unwrap()).is_err());
        }
        for address in ["127.0.0.1:7071", "[::1]:7071"] {
            assert!(validate_listen_address(address.parse().unwrap()).is_ok());
        }
    }
}
