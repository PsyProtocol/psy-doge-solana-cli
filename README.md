# psy-doge-solana-cli

Production CLI and local Bun tooling for the Dogecoin ↔ Solana bridge.

The Rust binary is a single multi-command tool: `doge-solana-cli`. The global
network defaults to the safe localhost profile; production/devnet commands should
always select devnet explicitly:

```bash
doge-solana-cli --network localhost|devnet <command> …
```

- **`localhost`** — local operator tooling. May start dogecoind, Electrs, a Solana
  validator, IBC pipeline, SP1 prover, block Sender, and a local Manager service.
  Complete local smoke is the dedicated subcommand `local-e2e`.
- **`devnet`** — public-network profile. Individual `deposit`, `withdraw`,
  `daemon`, and deployment commands start no implicit services. The explicit
  `tools/devnet/start.ts` supervisor starts only Sender, IBC/SP1, and the
  withdrawal daemon; it never starts dogecoind, Electrs, a Solana validator,
  Redis, or a Manager service.

Local Bun scripts live under `tools/local/`. Devnet program deployment and the
explicit production-service supervisor live under `tools/deploy/` and
`tools/devnet/`. Sibling repositories remain runtime dependencies for proving,
block submission, and on-chain programs; this repo orchestrates them but does
not vendor their sources.

## Layout

| Path | Role |
| --- | --- |
| `doge/` | Operator CLI crate (`doge-local-ops` package → binary `doge-solana-cli`) |
| `cli/` | Legacy bridge-management crate (`doge-bridge-cli`) |
| `tools/local/launcher.ts` | Local environment launcher (Bun) |
| `tools/local/runner.ts` | Internal implementation behind `local-e2e` |
| `tools/deploy/devnet.ts` | Devnet program deployment (separate from operator CLI) |
| `tools/devnet/start.ts` | Explicit devnet Sender + IBC/SP1 + withdrawal-daemon supervisor |

## Build the CLI

```bash
cargo build --release -p doge-local-ops
# binary:
#   doge/target/release/doge-solana-cli
```

Package name stays `doge-local-ops`; the installed/release binary name is always
`doge-solana-cli` (matches clap `name`).

### Subcommands

```bash
doge/target/release/doge-solana-cli --network localhost|devnet <subcommand> …
```

| Subcommand | Purpose |
| --- | --- |
| `deposit` | Build, broadcast, confirm, and record a Dogecoin custody deposit |
| `withdraw` | Snapshot withdrawals, build outputs-only Dogecoin tx, Manager 5/7 sign, off-chain broadcast confirmation |
| `daemon` | Operator daemon: poll unprocessed withdrawal snapshots and drive `withdraw` |
| `manager-service` | Local Manager HTTP service (`localhost` only) |
| `init-bridge` | Initialize bridge state from Dogecoin chain data |
| `local-e2e` | Explicit complete local smoke (`--network localhost` only) |

There is no separate `deposit_to_solana`, `process_withdrawal`, or
`local_manager_service` binary. Use the unified binary and the subcommands above.

### Withdrawal model (current)

- User burn → on-chain `request_withdrawal` + operator `snapshot_withdrawals`
- Operator builds an **outputs-only** Dogecoin transaction from the snapshot batch
- **Manager set 5-of-7** signs off-chain via the Manager service
- Broadcast + confirmation/finalize are **off-chain operator state** (store status transitions)
- **Not** in this flow: `authorize_withdrawal`, `PendingWithdrawal`, disc-17, or on-chain finalize; the Wormhole VAA still carries the outputs-only UTX0 payload.
- The only ZK path is SP1 **`block_update`** (deposit/chain tip), owned by the IBC pipeline + block sender

### Official Wormhole / Manager IDs (devnet)

| Component | ID |
| --- | --- |
| Wormhole Core (Solana devnet) | `3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5` |
| Wormhole Shim | `EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX` |
| Delegated Manager Set program | `wdmsTJP6YnsfeQjPuuEzGCrHmZvTmNy8VkxMCK8JkBX` |
| Manager set index | `1` (official Wormhole testnet/devnet set 1) |
| Dogecoin Wormhole chain ID | `65` |

Localhost smoke uses a deterministic local 5-of-7 Manager set (index `0`) and a
local Manager HTTP service. Devnet uses Manager set index `1` against an
**externally operated** Manager service — the CLI does not start one.

## Networks

### localhost — local tools and smoke

Requires [Bun](https://bun.sh). From this repository root:

```bash
bun install

# Bring up the local stack (may start dogecoind, Electrs, Solana validator,
# bridge init, users, and optionally IBC / Sender / SP1 / Manager)
bun tools/local/launcher.ts --network localhost

# Read-only path/binary validation (no services)
bun tools/local/launcher.ts --network localhost --preflight --no-build

# Explicit complete local validation (the only public full-flow entry)
doge/target/release/doge-solana-cli --network localhost local-e2e
```

`local-e2e` is the only public complete local-flow entry. The localhost launcher may
start dogecoind, Electrs, a Solana validator, IBC pipeline, SP1, Sender, and a
local Manager service as needed. Production operator commands (`deposit`,
`withdraw`, `daemon`) remain the same binary with `--network localhost`.

Compile-check the Bun entry points without running them:

```bash
bun build tools/local/launcher.ts --target=bun --outfile=/tmp/psy-doge-cli-local-launcher
bun build tools/local/runner.ts --target=bun --outfile=/tmp/psy-doge-cli-local-runner
```

### devnet — remote endpoints only

```bash
# Operator commands against public devnet endpoints (starts nothing local)
doge/target/release/doge-solana-cli --network devnet deposit …
doge/target/release/doge-solana-cli --network devnet withdraw …
doge/target/release/doge-solana-cli --network devnet daemon …
```

Individual devnet CLI commands start no implicit processes. The explicit
supervisor consumes externally operated Solana RPC, Dogecoin testnet Electrs,
Redis, and Manager endpoints, then starts only the local production workers:
Sender, IBC/SP1, and the withdrawal daemon. It never starts dogecoind, Electrs,
a Solana validator, Redis, or a Manager service. An available external Manager
service is required for withdrawal signing.

Program deployment is **not** a CLI subcommand. It deploys/upgrades only the
five Psy programs and verifies the official Wormhole Core/Shim; bridge-state
initialization remains the explicit `init-bridge` operator action:

```bash
bun tools/deploy/devnet.ts --network devnet \
  --payer /secure/payer.json \
  --program-key-dir /secure/program-keys \
  --preflight
```

After deploying the five Psy programs, initialize the Bridge State directly with
`init-bridge`. Fresh deployments use the current `6,224`-byte snapshot layout;
no layout migration step is required.

The production Manager URL is an external prerequisite, not Wormholescan's
standard Guardian VAA endpoint. It must implement both Manager transaction
registration (`POST /api/v1/withdrawals`) and Manager signatures
(`GET /v1/manager/signed_vaa/...`), and the DBjo emitter must be allowlisted.
The public Wormholescan Testnet API currently returns `404` for the Manager
route, so it is intentionally not a runnable default.

```bash
bun tools/devnet/start.ts --network devnet --preflight \
  --operator-keypair /secure/operator.json \
  --payer-keypair /secure/payer.json \
  --operator-store /secure/operator-store.sqlite \
  --sender-token-file /secure/sender-token \
  --redis-url rediss://redis.example/0 \
  --redis-username psy-doge \
  --redis-password-file /secure/redis-password \
  --manager-url https://manager.example \
  --recipient-ata <PDOGE_RECIPIENT_ATA> \
  --doge-mint HJya3v4mPhq3sfWvEL45nenCxVvDzGRSzTPNmAdiZWQX
```

Remove `--preflight` to run. The supervisor verifies devnet genesis, five
required program accounts, official Core/Shim, Dogecoin Manager chain `65` set
`1`, Electrs, authenticated Redis, a parseable Manager-signature route,
executable release artifacts, key-file modes, operator/mint/ATA bindings, and
the exact Bridge State layout before starting anything.
Ctrl+C/SIGTERM stops daemon, IBC/SP1, and Sender in reverse order.

## Sibling runtime dependencies

Checkout siblings next to this repo (default projects dir =
`path.resolve(CLI_REPO, "..")`). Expected directory names:

| Directory | Role |
| --- | --- |
| `psy-doge-solana-bridge` | On-chain programs, bridge config, JS/Rust clients |
| `solana-doge-ibc` | IBC block pipeline (`e2e_block_pipeline`) and related services |
| `solana-doge-bridge-block-sender` | Isolated block-sender HTTP service |
| `psy-bridge-sp1` | SP1 `gen-proof` + block-transition ELF / VK |
| `dogecoin` | Dogecoin Core (regtest `dogecoind` / `dogecoin-cli`) |
| `electrs-doge` | Electrs for Dogecoin |

The localhost launcher discovers these from the CLI checkout and starts/consumes
their **release** artifacts when running the complete local validation. Build them
in their own repos before `doge-solana-cli --network localhost local-e2e` or the
explicit devnet supervisor. Devnet never launches local chain infrastructure.

JS dependencies for the local tools (`@solana/web3.js`, `@solana/spl-token`,
`bs58`) are declared in this repo’s `package.json`. Do not treat
`../psy-doge-solana-bridge/clients/js/node_modules` as a long-term import path.

## Rust library dependencies

The `doge` crate path-depends on bridge libraries (or git equivalents):

- `doge-bridge-client`
- `psy-bridge-core`
- `psy-doge-solana-core`

plus DLC helpers (`doge-light-client`, `psy-doge-bridge-helper`, `psy-doge-data-link`).

## Safety

- Never commit WIFs, keypair JSON secret arrays, or operator store secrets.
- Evidence and funding artifacts under `/tmp` and `*-evidence.json` are gitignored.
- Do not push from QA worktrees unless explicitly instructed.
