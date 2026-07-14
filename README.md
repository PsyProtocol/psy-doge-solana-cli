# Doge Bridge Solana CLI

CLI tools for managing the Doge↔Solana bridge on devnet.

## Packages

- `doge-bridge-cli` — Bridge management CLI (initialize, create mint, setup users)
- `doge-local-ops` — Operator CLI (deposit-to-solana, process-withdrawal)

## Devnet Scripts

### CLI bin targets (`doge-bridge-cli`)
- `devnet_block_update` — Submit block_update with SP1 proof to devnet
- `devnet_deposit` — Full deposit flow: create ATA → reinit buffer → block_update → mint pDOGE
- `devnet_burn` — Burn pDOGE (request_withdrawal) + snapshot_withdrawals
- `init_wormhole` — Initialize Wormhole Core Bridge on devnet
- `check_wormhole` — Check Wormhole PDA account existence

### Operator CLI (`doge-local-ops`)
- `deposit_to_solana` — End-to-end deposit: Dogecoin regtest → SP1 proof → Solana block_update → mint pDOGE
- `process_withdrawal` — End-to-end withdrawal: burn pDOGE → Dogecoin tx → SP1 proof → process_withdrawal + Wormhole VAA

## Dependencies

This workspace depends on `psy-doge-solana-bridge` libraries via git:
- `doge-bridge-client` — Rust client library
- `psy-bridge-core` — Core bridge types and crypto
- `psy-doge-solana-core` — Solana-specific bridge types

## Build

```bash
cargo build --release
```

## Devnet Addresses

See the Wormhole integration document for all deployed addresses.
