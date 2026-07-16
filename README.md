# Doge Bridge Solana CLI

Production CLI tools for user and operator actions on the Doge↔Solana bridge.

## Packages

- `doge-bridge-cli` — Bridge management CLI (initialize, create mint, setup users)
- `doge-local-ops` — Operator CLI (deposit-to-solana, process-withdrawal)

## Production commands

### CLI bin targets (`doge-bridge-cli`)
- `devnet_block_update` — Submit an explicitly supplied block_update proof to devnet
- `devnet_deposit` — Submit an explicitly prepared deposit flow to devnet
- `devnet_burn` — Burn pDOGE (request_withdrawal) and snapshot withdrawals
- `init_wormhole` — Initialize Wormhole Core Bridge on devnet
- `check_wormhole` — Check Wormhole PDA account existence

### Operator CLI (`doge-local-ops`)
- `deposit_to_solana` — Build, broadcast, confirm, and record a Dogecoin custody deposit; the IBC pipeline owns block detection, the real deposit witness, SP1 `block_update`, and mint processing
- `process_withdrawal` — Execute the atomic authorize/VAA, manager signing/broadcast, confirmation, and finalize flow

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
