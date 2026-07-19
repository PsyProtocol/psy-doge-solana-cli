#!/usr/bin/env bun

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { parseArgs } from "node:util";
import { createHash } from "node:crypto";
import { Keypair, PublicKey } from "@solana/web3.js";

const CLI_REPO = path.resolve(import.meta.dir, "../..");
const DEFAULT_PROJECTS_DIR = path.resolve(CLI_REPO, "..");
const DEFAULT_RPC_URL = "https://api.devnet.solana.com";
const DEFAULT_WS_URL = "wss://api.devnet.solana.com";
const DEFAULT_ELECTRS_URL = "https://doge-electrs-testnet-demo.qed.me";
const DEFAULT_MANAGER_URL = "https://api.testnet.wormholescan.io";
const DEFAULT_STATE_DIR = path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"), "psy-doge-devnet");
const DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const DOGE_BRIDGE_PROGRAM = "9HdfoY6yYFLo3sQ5qMv9tHHgXzB3AnA2GXXyedeWrLdN";
const PENDING_MINT_PROGRAM = "DHB58D8HbnRM7QQiJ37iE3YjCfUbzbhpcc2Bf5rAXkua";
const TXO_BUFFER_PROGRAM = "9N217cCfEhickevyD3amY1BQh8P8Hay7CKKWa5kgrgHs";
const GENERIC_BUFFER_PROGRAM = "marxYjRRhMAmfyGPNwkKEgwzKsSNfmKQ4gzMLadZxuz";
const MANUAL_CLAIM_PROGRAM = "BsMpUmLvjjkvgrmQWJeaitmbQx1L5uXi5woXBbuDyUBJ";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const OFFICIAL_WORMHOLE_CORE = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";
const OFFICIAL_WORMHOLE_SHIM = "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";
const MANAGER_SET_INDEX_PDA = "92cvQngpTU8xduGFySpZxAYC6neJShokHYoi841obg1o";
const MANAGER_SET_PDA = "FwX9YtbNrDyjs6XYQFtfCgSXwKZjMpXhErPLnmPFydF6";
const MANAGER_SET_PROGRAM = "wdmsTJP6YnsfeQjPuuEzGCrHmZvTmNy8VkxMCK8JkBX";
const EXPECTED_MANAGER_SET_BYTES = Buffer.from(
    "010507"
    + "02349de56ca5dd06db8660419d6f150662e0f04febdbf6512d7cfe78c23b51491c"
    + "035163bfd9518b0a536a17f330a1589fe21d7404b51f525a0a990a65a701952ebb"
    + "036d40b0b85bca49e41f05a26950578bb13a424507ce34a80f83d3cf601e25818b"
    + "0307681002ae28b9399e828d0f46d54c31d5d6ff187b3bdddc6615987a466455f5"
    + "0375abc8955c8a8c875ee1febd157132adcc1b992d69a946e83485b8360e23a277"
    + "030212d206546216917a75533ed6c975f8f794ba0d8a7fb84dedf65ebb20e64841"
    + "037ff483369b52bd87a73f23413dd8fcace71de7f7823c5c9120f1e9cfe5733a88",
    "hex",
);
const TESTNET_BLOCK_VK = "00b25e2fe5866751a38e5ca4d975b30b4187f3e0528a06dc86edc6e9a8b9cc02";
const BRIDGE_STATE_PDA = "HATWnTqCHP3ZnDstJcw9jmeJ5zdjxpUParDGh5Sfonen";
const BRIDGE_STATE_SIZE = 6_224;
const HEADER_SIZE = 320;
const FINALIZED_HEIGHT_OFFSET = 268;
const CUSTODIAN_HASH_OFFSET = 5_936;
const CONFIG_OFFSET = 6_080;
const CONFIG_SIZE = 48;
const OPERATOR_OFFSET = 6_128;
const MINT_OFFSET = 6_192;
const MINT_SIZE = 32;
/// Derive the official Manager set 1 custodian wallet config hash from the
/// current Bridge State PDA + the deployed Manager set bytes (Type|M|N|keys)
/// using the exact 264-byte custody wallet config layout, and assert it equals
/// the canonical hash for this deployment. The PDA is the custody-script
/// emitter; the manager keys + threshold come from EXPECTED_MANAGER_SET_BYTES;
/// config_id is 1 and network_type is 0 for official testnet set 1. This stays
/// byte-identical to the DLC helper, CLI, IBC, and on-chain doge-bridge.
function custodyWalletConfigHash(emitterHex: string, managerSetBytes: Buffer, configId: number, networkType: number): Buffer {
    // managerSetBytes layout: Type(1) | M(1) | N(1) | Pubkeys(N*33)
    const n = managerSetBytes[2];
    if (managerSetBytes.length < 3 + n * 33) fail("EXPECTED_MANAGER_SET_BYTES is truncated");
    // 32 emitter + 7*32 x-only keys + 4 config_id + 2 y_parity + 2 network_type
    const walletConfig = Buffer.alloc(264);
    Buffer.from(emitterHex, "hex").copy(walletConfig, 0);
    let yParity = 0;
    for (let i = 0; i < n; i++) {
        const compressed = managerSetBytes.subarray(3 + i * 33, 3 + (i + 1) * 33);
        if (compressed.length !== 33) fail(`manager set key ${i} is not 33 bytes`);
        compressed.copy(walletConfig, 32 + i * 32, 1, 33); // x-only (drop parity byte)
        if (compressed[0] === 0x03) yParity |= 1 << i;
    }
    walletConfig.writeUInt32LE(configId, 256);
    walletConfig.writeUInt16LE(yParity, 260);
    walletConfig.writeUInt16LE(networkType, 262);
    return createHash("sha256").update(walletConfig).digest();
}
const EXPECTED_OFFICIAL_CUSTODY_HASH_HEX = "2621f9ac4de46226f85b48bcf2e20c87e6bb62ff946a9b12becb8c35a4e90ab0";
const OFFICIAL_CUSTODY_HASH = custodyWalletConfigHash(pubkeyHex(BRIDGE_STATE_PDA), EXPECTED_MANAGER_SET_BYTES, 1, 0);
if (OFFICIAL_CUSTODY_HASH.toString("hex") !== EXPECTED_OFFICIAL_CUSTODY_HASH_HEX) {
    fail(`derived official custody hash ${OFFICIAL_CUSTODY_HASH.toString("hex")} does not match canonical ${EXPECTED_OFFICIAL_CUSTODY_HASH_HEX} for Bridge State PDA ${BRIDGE_STATE_PDA}`);
}

export type ProcessRole = "sender" | "ibc" | "daemon";
export type ProcessSpec = { role: ProcessRole; command: string[]; cwd: string; env?: Record<string, string> };
export type SupervisorOptions = {
    dryRun: boolean;
    projectsDir: string;
    stateDir: string;
    rpcUrl: string;
    wsUrl: string;
    electrsUrl: string;
    managerUrl: string;
    redisUrl: string;
    redisUsername?: string;
    redisPasswordFile?: string;
    senderListenPort: number;
    senderPublicUrl: string;
    senderTokenFile: string;
    operatorKeypair: string;
    payerKeypair: string;
    operatorStore: string;
    recipientAtas: string[];
    dogeMint: string;
    startHeight?: number;
    redisSeed: number;
    evidenceDir: string;
    cliBin: string;
    ibcBin: string;
    senderBin: string;
    genProofBin: string;
    blockElf: string;
};
export type RuntimeInputs = {
    senderToken: string;
    redisPassword?: string;
    operatorSeed: string;
    payerSeed: string;
    initialHeader: string;
    configParams: string;
    startHeight: number;
};
export type ProcessPlan = { sender: ProcessSpec; ibc: ProcessSpec; daemon: ProcessSpec };
type JsonObject = Record<string, unknown>;
type KeyMaterial = { seedHex: string; pubkey: string };
type RunningProcess = { role: ProcessRole; child: Bun.Subprocess; stdoutLog: string; stderrLog: string };

function usage(): string {
    return `Start Psy Doge production services against Solana devnet

Usage:
  bun tools/devnet/start.ts --network devnet --preflight [options]
  bun tools/devnet/start.ts --network devnet [options]

Required:
  --operator-keypair <path>    Solana operator keypair JSON (mode 600)
  --payer-keypair <path>       Solana fee-payer keypair JSON (mode 600)
  --operator-store <path>      Durable withdrawal OperatorStore SQLite path
  --sender-token-file <path>   Non-empty Bearer token file (mode 600)
  --recipient-ata <pubkey>     Recipient pDOGE ATA to auto-claim; repeatable
  --doge-mint <pubkey>         Deployed pDOGE mint
  --redis-url <rediss-url>     External TLS Redis checkpoint store

Remote services:
  --rpc-url <https-url>        Solana devnet RPC (default: ${DEFAULT_RPC_URL})
  --ws-url <wss-url>           Matching Solana devnet WebSocket RPC
  --electrs-url <https-url>    External Dogecoin testnet Electrs
  --manager-url <https-url>    External production Manager REST base
  --redis-username <name>      Optional Redis ACL username
  --redis-password-file <path> Optional Redis password file (mode 600)
  --sender-public-url <url>    Must equal supervised http://127.0.0.1:<port>
  --sender-listen-port <n>     Local sender port (default: 3000)

Pipeline state:
  --start-height <n>           Required when Redis has no matching checkpoint
  --redis-seed <n>             Checkpoint namespace seed (default: 1337)
  --evidence-dir <path>        Durable block-proof evidence root
  --state-dir <path>           Logs and generated non-secret runtime state

Artifacts:
  --projects-dir <path>        Sibling repository root
  --cli-bin <path>             doge-solana-cli release binary
  --ibc-bin <path>             e2e_block_pipeline release binary
  --sender-bin <path>          built sender dist/index.js
  --gen-proof-bin <path>       SP1 gen-proof release binary
  --block-elf <path>           embedded testnet block-transition ELF

Lifecycle:
  --preflight                  Validate everything; start no process
  -h, --help                   Show this help

This script starts only Sender, IBC/SP1, and the withdrawal daemon. It never
starts dogecoind, Electrs, a Solana validator, Redis, or a Manager service.`;
}

function fail(message: string): never { throw new Error(message); }
function isObject(value: unknown): value is JsonObject { return typeof value === "object" && value !== null && !Array.isArray(value); }
function asString(value: unknown, fallback = ""): string { return typeof value === "string" && value.length > 0 ? value : fallback; }
function parseInteger(value: unknown, flag: string, minimum: number): number | undefined {
    if (value === undefined) return undefined;
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < minimum) fail(`${flag} must be an integer >= ${minimum}`);
    return parsed;
}

export function requireRemoteUrl(value: string, flag: string, protocols: string[]): string {
    let url: URL;
    try { url = new URL(value); } catch { fail(`${flag} must be a valid URL`); }
    if (!protocols.includes(url.protocol)) fail(`${flag} must use ${protocols.join(" or ")}`);
    if (url.username || url.password) fail(`${flag} must not embed credentials; use a mode-600 credential file`);
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    const privateName = host === "localhost" || host.endsWith(".localhost");
    const privateIpv4 = /^(127\.|0\.|10\.|192\.168\.|169\.254\.)/.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    const privateIpv6 = host === "::" || host === "::1" || host.startsWith("fc") || host.startsWith("fd") || /^fe[89ab]/.test(host);
    if (privateName || privateIpv4 || privateIpv6) fail(`${flag} must be externally operated; local/private host '${url.hostname}' is forbidden`);
    return url.toString().replace(/\/$/, "");
}

function resolveOptions(): SupervisorOptions | null {
    const { values } = parseArgs({
        args: Bun.argv.slice(2), strict: true, allowPositionals: false,
        options: {
            help: { type: "boolean", short: "h" }, network: { type: "string" }, preflight: { type: "boolean" },
            "projects-dir": { type: "string" }, "state-dir": { type: "string" }, "rpc-url": { type: "string" },
            "ws-url": { type: "string" }, "electrs-url": { type: "string" }, "manager-url": { type: "string" },
            "redis-url": { type: "string" }, "redis-username": { type: "string" }, "redis-password-file": { type: "string" },
            "sender-listen-port": { type: "string" }, "sender-public-url": { type: "string" },
            "sender-token-file": { type: "string" }, "operator-keypair": { type: "string" }, "payer-keypair": { type: "string" },
            "operator-store": { type: "string" }, "recipient-ata": { type: "string", multiple: true }, "doge-mint": { type: "string" },
            "start-height": { type: "string" }, "redis-seed": { type: "string" }, "evidence-dir": { type: "string" },
            "cli-bin": { type: "string" }, "ibc-bin": { type: "string" }, "sender-bin": { type: "string" },
            "gen-proof-bin": { type: "string" }, "block-elf": { type: "string" },
        },
    });
    if (values.help) { console.log(usage()); return null; }
    if (values.network !== "devnet") fail("--network devnet is required");
    const required = (flag: string, value: unknown): string => {
        const text = asString(value);
        if (!text) fail(`${flag} is required`);
        return text;
    };
    const projectsDir = path.resolve(asString(values["projects-dir"], DEFAULT_PROJECTS_DIR));
    const senderListenPort = parseInteger(values["sender-listen-port"], "--sender-listen-port", 1) ?? 3000;
    if (senderListenPort > 65_535) fail("--sender-listen-port must be <= 65535");
    const senderPublicUrl = asString(values["sender-public-url"], `http://127.0.0.1:${senderListenPort}`).replace(/\/$/, "");
    const expectedSenderUrl = `http://127.0.0.1:${senderListenPort}`;
    if (senderPublicUrl !== expectedSenderUrl) fail(`--sender-public-url must be ${expectedSenderUrl}; IBC credentials may only target the supervised local Sender`);
    return {
        dryRun: Boolean(values.preflight), projectsDir,
        stateDir: path.resolve(asString(values["state-dir"], DEFAULT_STATE_DIR)),
        rpcUrl: requireRemoteUrl(asString(values["rpc-url"], DEFAULT_RPC_URL), "--rpc-url", ["https:"]),
        wsUrl: requireRemoteUrl(asString(values["ws-url"], DEFAULT_WS_URL), "--ws-url", ["wss:"]),
        electrsUrl: requireRemoteUrl(asString(values["electrs-url"], DEFAULT_ELECTRS_URL), "--electrs-url", ["https:"]),
        managerUrl: requireRemoteUrl(asString(values["manager-url"], DEFAULT_MANAGER_URL), "--manager-url", ["https:"]),
        redisUrl: requireRemoteUrl(required("--redis-url", values["redis-url"]), "--redis-url", ["rediss:"]),
        redisUsername: values["redis-username"] ? String(values["redis-username"]) : undefined,
        redisPasswordFile: values["redis-password-file"] ? path.resolve(String(values["redis-password-file"])) : undefined,
        senderListenPort, senderPublicUrl,
        senderTokenFile: path.resolve(required("--sender-token-file", values["sender-token-file"])),
        operatorKeypair: path.resolve(required("--operator-keypair", values["operator-keypair"])),
        payerKeypair: path.resolve(required("--payer-keypair", values["payer-keypair"])),
        operatorStore: path.resolve(required("--operator-store", values["operator-store"])),
        recipientAtas: (values["recipient-ata"] || []).map(String), dogeMint: required("--doge-mint", values["doge-mint"]),
        startHeight: parseInteger(values["start-height"], "--start-height", 1),
        redisSeed: parseInteger(values["redis-seed"], "--redis-seed", 0) ?? 1_337,
        evidenceDir: path.resolve(asString(values["evidence-dir"], path.join(DEFAULT_STATE_DIR, "block-proof-evidence"))),
        cliBin: path.resolve(asString(values["cli-bin"], path.join(CLI_REPO, "doge/target/release/doge-solana-cli"))),
        ibcBin: path.resolve(asString(values["ibc-bin"], path.join(projectsDir, "solana-doge-ibc/target/release/examples/e2e_block_pipeline"))),
        senderBin: path.resolve(asString(values["sender-bin"], path.join(projectsDir, "solana-doge-bridge-block-sender/apps/sol-send-server/dist/index.js"))),
        genProofBin: path.resolve(asString(values["gen-proof-bin"], path.join(projectsDir, "psy-bridge-sp1/target/release/gen-proof"))),
        blockElf: path.resolve(asString(values["block-elf"], path.join(projectsDir, "psy-bridge-sp1/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/block-transition-testnet"))),
    };
}

function assertMode600(filePath: string, label: string): void {
    if (!fs.existsSync(filePath)) fail(`${label} is missing: ${filePath}`);
    if ((fs.statSync(filePath).mode & 0o777) !== 0o600) fail(`${label} must have mode 600: ${filePath}`);
}
function readSecretFile(filePath: string, label: string): string {
    assertMode600(filePath, label);
    const value = fs.readFileSync(filePath, "utf8").trim();
    if (!value) fail(`${label} must not be empty`);
    return value;
}
function readKeyMaterial(filePath: string, label: string): KeyMaterial {
    assertMode600(filePath, label);
    const value: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
    if (!Array.isArray(value) || value.length !== 64 || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) fail(`${label} must contain a 64-byte Solana keypair array`);
    const bytes = Uint8Array.from(value as number[]);
    const keypair = Keypair.fromSecretKey(bytes);
    return { seedHex: Buffer.from(bytes.subarray(0, 32)).toString("hex"), pubkey: keypair.publicKey.toBase58() };
}

async function jsonRpc(url: string, method: string, params: unknown[] = []): Promise<unknown> {
    const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, redirect: "error", signal: AbortSignal.timeout(15_000), body: JSON.stringify({ jsonrpc: "2.0", id: method, method, params }) });
    const text = await response.text();
    if (!response.ok) fail(`${method} returned HTTP ${response.status}: ${text}`);
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { fail(`${method} returned invalid JSON`); }
    if (!isObject(parsed)) fail(`${method} returned a non-object response`);
    if (parsed.error !== undefined && parsed.error !== null) fail(`${method} RPC error: ${JSON.stringify(parsed.error)}`);
    return parsed.result;
}
function accountValue(result: unknown, address: string): JsonObject {
    if (!isObject(result) || !isObject(result.value)) fail(`Solana account ${address} is absent`);
    return result.value;
}
function decodeAccount(result: unknown, address: string): Buffer {
    const value = accountValue(result, address);
    const data = value.data;
    if (!Array.isArray(data) || typeof data[0] !== "string" || data[1] !== "base64") fail(`Invalid account encoding for ${address}`);
    return Buffer.from(data[0], "base64");
}
export function pubkeyHex(value: string): string { return Buffer.from(new PublicKey(value).toBytes()).toString("hex"); }
async function readRemoteText(url: string, label: string): Promise<string> {
    const response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(15_000) });
    if (!response.ok) fail(`${label} returned HTTP ${response.status}: ${await response.text()}`);
    return (await response.text()).trim();
}
function authenticatedRedisUrl(base: string, username: string | undefined, password: string | undefined): string {
    if (!password) return base;
    const url = new URL(base);
    if (username) url.username = username;
    url.password = password;
    return url.toString();
}
function redisCommand(parts: string[]): string { return `*${parts.length}\r\n${parts.map((part) => `$${Buffer.byteLength(part)}\r\n${part}\r\n`).join("")}`; }
async function probeRedis(redisUrl: string, username: string | undefined, password: string | undefined): Promise<void> {
    const url = new URL(redisUrl);
    const commands: string[][] = [];
    if (password) commands.push(username ? ["AUTH", username, password] : ["AUTH", password]);
    const database = url.pathname.replace(/^\//, "");
    if (database) commands.push(["SELECT", database]);
    commands.push(["PING"]);
    const request = commands.map(redisCommand).join("");
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    let settled = false;
    let responses = 0;
    let buffered = "";
    const socket = tls.connect({ host: url.hostname, port: Number(url.port || 6380), servername: url.hostname });
    const finish = (error?: Error): void => {
        if (settled) return;
        settled = true;
        socket.destroy();
        error ? reject(error) : resolve();
    };
    socket.setTimeout(10_000);
    socket.once("secureConnect", () => socket.write(request));
    socket.on("data", (chunk: Buffer) => {
        buffered += chunk.toString("utf8");
        for (;;) {
            const end = buffered.indexOf("\r\n");
            if (end < 0) break;
            const line = buffered.slice(0, end);
            buffered = buffered.slice(end + 2);
            if (!line) continue;
            if (line.startsWith("-")) return finish(new Error(`Redis rejected preflight command: ${line.slice(1)}`));
            if (!line.startsWith("+") && !line.startsWith(":")) return finish(new Error("Redis returned an unsupported preflight response"));
            responses += 1;
            if (responses === commands.length) return line === "+PONG" ? finish() : finish(new Error("Redis PING did not return PONG"));
        }
    });
    socket.once("timeout", () => finish(new Error("Redis preflight timed out")));
    socket.once("error", (error: Error) => finish(new Error(`Redis preflight connection failed: ${error.message}`)));
    await promise;
}

async function preflight(options: SupervisorOptions): Promise<RuntimeInputs> {
    for (const [label, filePath] of [
        ["CLI binary", options.cliBin], ["IBC binary", options.ibcBin], ["Sender binary", options.senderBin],
        ["SP1 gen-proof", options.genProofBin], ["SP1 testnet ELF", options.blockElf],
    ] as const) if (!fs.existsSync(filePath)) fail(`${label} is missing: ${filePath}`);
    for (const filePath of [options.cliBin, options.ibcBin, options.genProofBin]) fs.accessSync(filePath, fs.constants.X_OK);
    if (options.recipientAtas.length === 0) fail("At least one --recipient-ata is required");
    for (const ata of options.recipientAtas) new PublicKey(ata);
    new PublicKey(options.dogeMint);
    const operator = readKeyMaterial(options.operatorKeypair, "Operator keypair");
    const payer = readKeyMaterial(options.payerKeypair, "Payer keypair");
    const senderToken = readSecretFile(options.senderTokenFile, "Sender token file");
    if (senderToken.length < 32) fail("Sender Bearer token must contain at least 32 characters");
    const redisPassword = options.redisPasswordFile ? readSecretFile(options.redisPasswordFile, "Redis password file") : undefined;

    const bridgeStateResult = await jsonRpc(options.rpcUrl, "getAccountInfo", [BRIDGE_STATE_PDA, { encoding: "base64", commitment: "confirmed" }]);
    const bridgeStateAccount = accountValue(bridgeStateResult, BRIDGE_STATE_PDA);
    if (bridgeStateAccount.owner !== DOGE_BRIDGE_PROGRAM) fail(`Bridge State owner ${bridgeStateAccount.owner} is not ${DOGE_BRIDGE_PROGRAM}`);
    const bridgeState = decodeAccount(bridgeStateResult, BRIDGE_STATE_PDA);
    if (bridgeState.length !== BRIDGE_STATE_SIZE) fail(`Bridge State is ${bridgeState.length} bytes; current snapshot source requires a deployed ${BRIDGE_STATE_SIZE}-byte layout before Sender/IBC/daemon can start`);

    const genesis = String(await jsonRpc(options.rpcUrl, "getGenesisHash"));
    if (genesis !== DEVNET_GENESIS_HASH) fail(`RPC genesis ${genesis} is not Solana devnet ${DEVNET_GENESIS_HASH}`);
    for (const id of [DOGE_BRIDGE_PROGRAM, PENDING_MINT_PROGRAM, TXO_BUFFER_PROGRAM, GENERIC_BUFFER_PROGRAM, MANUAL_CLAIM_PROGRAM, OFFICIAL_WORMHOLE_CORE, OFFICIAL_WORMHOLE_SHIM]) {
        const account = accountValue(await jsonRpc(options.rpcUrl, "getAccountInfo", [id, { encoding: "base64", commitment: "confirmed" }]), id);
        if (account.executable !== true) fail(`Required program ${id} is not executable on devnet`);
    }
    const managerIndexResult = await jsonRpc(options.rpcUrl, "getAccountInfo", [MANAGER_SET_INDEX_PDA, { encoding: "base64", commitment: "confirmed" }]);
    if (accountValue(managerIndexResult, MANAGER_SET_INDEX_PDA).owner !== MANAGER_SET_PROGRAM) fail("ManagerSetIndex owner mismatch");
    const managerIndex = decodeAccount(managerIndexResult, MANAGER_SET_INDEX_PDA);
    if (managerIndex.length < 14 || managerIndex.readUInt16LE(8) !== 65 || managerIndex.readUInt32LE(10) !== 1) fail("Dogecoin ManagerSetIndex is not chain 65 / set 1");
    const managerSetResult = await jsonRpc(options.rpcUrl, "getAccountInfo", [MANAGER_SET_PDA, { encoding: "base64", commitment: "confirmed" }]);
    if (accountValue(managerSetResult, MANAGER_SET_PDA).owner !== MANAGER_SET_PROGRAM) fail("ManagerSet owner mismatch");
    const managerSet = decodeAccount(managerSetResult, MANAGER_SET_PDA);
    if (managerSet.length < 18 + EXPECTED_MANAGER_SET_BYTES.length || !managerSet.subarray(18, 18 + EXPECTED_MANAGER_SET_BYTES.length).equals(EXPECTED_MANAGER_SET_BYTES)) fail("Dogecoin Manager set 1 bytes mismatch");
    const custodianHash = bridgeState.subarray(CUSTODIAN_HASH_OFFSET, CUSTODIAN_HASH_OFFSET + 32);
    if (!custodianHash.equals(OFFICIAL_CUSTODY_HASH)) fail(`Bridge custodian hash ${custodianHash.toString("hex")} does not match official Manager set 1 custody hash ${OFFICIAL_CUSTODY_HASH.toString("hex")} for Bridge State PDA ${BRIDGE_STATE_PDA}`);
    const stateOperator = new PublicKey(bridgeState.subarray(OPERATOR_OFFSET, OPERATOR_OFFSET + 32)).toBase58();
    if (stateOperator !== operator.pubkey) fail(`Operator keypair ${operator.pubkey} does not match Bridge State operator ${stateOperator}`);
    const stateMint = new PublicKey(bridgeState.subarray(MINT_OFFSET, MINT_OFFSET + MINT_SIZE)).toBase58();
    if (stateMint !== options.dogeMint) fail(`Configured pDOGE mint ${options.dogeMint} does not match Bridge State mint ${stateMint}`);
    const mintResult = await jsonRpc(options.rpcUrl, "getAccountInfo", [stateMint, { encoding: "base64", commitment: "confirmed" }]);
    if (accountValue(mintResult, stateMint).owner !== TOKEN_PROGRAM) fail(`pDOGE mint is not owned by the SPL Token program`);
    const mintData = decodeAccount(mintResult, stateMint);
    const bridgePdaBytes = new PublicKey(BRIDGE_STATE_PDA).toBytes();
    if (mintData.length < 82 || mintData.readUInt32LE(0) !== 1 || !mintData.subarray(4, 36).equals(bridgePdaBytes) || mintData[44] !== 8 || mintData[45] !== 1 || mintData.readUInt32LE(46) !== 0) fail("pDOGE mint must be initialized with 8 decimals, Bridge State mint authority, and no freeze authority");
    for (const ata of options.recipientAtas) {
        const accountResult = await jsonRpc(options.rpcUrl, "getAccountInfo", [ata, { encoding: "base64", commitment: "confirmed" }]);
        if (accountValue(accountResult, ata).owner !== TOKEN_PROGRAM) fail(`Recipient ATA ${ata} is not owned by the SPL Token program`);
        const ataData = decodeAccount(accountResult, ata);
        if (ataData.length < 165 || !ataData.subarray(0, 32).equals(new PublicKey(stateMint).toBytes())) fail(`Recipient ATA ${ata} is not for pDOGE mint ${stateMint}`);
    }
    const payerBalance = Number(await jsonRpc(options.rpcUrl, "getBalance", [payer.pubkey, { commitment: "confirmed" }]).then((value) => isObject(value) ? value.value : undefined));
    if (!Number.isSafeInteger(payerBalance) || payerBalance < 1_000_000_000) fail(`Payer ${payer.pubkey} needs at least 1 SOL`);
    const electrsTip = Number(await readRemoteText(`${options.electrsUrl}/blocks/tip/height`, "Electrs tip"));
    if (!Number.isSafeInteger(electrsTip) || electrsTip < 1) fail(`Invalid Electrs tip '${electrsTip}'`);
    const startHeight = options.startHeight ?? bridgeState.readUInt32LE(FINALIZED_HEIGHT_OFFSET);
    if (startHeight > electrsTip - 1) fail(`Start height ${startHeight} is above finalized Electrs height ${electrsTip - 1}`);
    await probeRedis(options.redisUrl, options.redisUsername, redisPassword);
    const managerRoute = `${options.managerUrl}/v1/manager/signed_vaa/1/${pubkeyHex(BRIDGE_STATE_PDA)}/0`;
    const managerProbe = await fetch(managerRoute, { redirect: "error", signal: AbortSignal.timeout(15_000) });
    const managerBody = await managerProbe.text();
    if (!managerProbe.ok || !(managerProbe.headers.get("content-type") || "").toLowerCase().includes("json")) fail(`Manager service route ${managerRoute} returned HTTP ${managerProbe.status}; production Manager signing is unavailable`);
    let managerJson: unknown;
    try { managerJson = JSON.parse(managerBody); } catch { fail(`Manager service route ${managerRoute} returned invalid JSON`); }
    if (!isObject(managerJson) || typeof managerJson.vaaHash !== "string") fail(`Manager service route ${managerRoute} did not return a manager-signature response with vaaHash`);
    const configParams = bridgeState.subarray(CONFIG_OFFSET, CONFIG_OFFSET + CONFIG_SIZE).toString("hex");
    const initialHeader = bridgeState.subarray(0, HEADER_SIZE).toString("hex");
    console.log(`[preflight] devnet genesis=${genesis} Electrs tip=${electrsTip} start=${startHeight}`);
    console.log(`[preflight] programs=${DOGE_BRIDGE_PROGRAM}/${PENDING_MINT_PROGRAM}/${TXO_BUFFER_PROGRAM}/${GENERIC_BUFFER_PROGRAM}/${MANUAL_CLAIM_PROGRAM} Core=${OFFICIAL_WORMHOLE_CORE} Shim=${OFFICIAL_WORMHOLE_SHIM}`);
    console.log(`[preflight] Manager chain=65 set=1 operator=${operator.pubkey} payer=${payer.pubkey}`);
    return { senderToken, redisPassword, operatorSeed: operator.seedHex, payerSeed: payer.seedHex, initialHeader, configParams, startHeight };
}

function commandText(command: string[]): string { return command.map((value) => /^[A-Za-z0-9_./:=,@+-]+$/.test(value) ? value : JSON.stringify(value)).join(" "); }
export function processSpecs(options: SupervisorOptions, runtime: RuntimeInputs): ProcessPlan {
    const sender: ProcessSpec = {
        role: "sender", command: ["node", options.senderBin], cwd: path.dirname(options.senderBin),
        env: { API_TOKEN: runtime.senderToken, SOL_PAYER_SECRET_KEY: runtime.payerSeed, SOL_OPERATOR_SECRET_KEY: runtime.operatorSeed, SOL_RPC_URL: options.rpcUrl, SOL_WEBSOCKET_URL: options.wsUrl, NEEDS_AIRDROP: "false", LISTEN_PORT: String(options.senderListenPort), DOGE_BRIDGE_PROGRAM_ID: DOGE_BRIDGE_PROGRAM, PENDING_MINT_BUFFER_PROGRAM_ID: PENDING_MINT_PROGRAM, TXO_BUFFER_PROGRAM_ID: TXO_BUFFER_PROGRAM },
    };
    const ibc: ProcessSpec = {
        role: "ibc", command: [options.ibcBin], cwd: path.dirname(options.ibcBin),
        env: { DOGE_NETWORK: "testnet", DOGE_ELECTRS_URL: options.electrsUrl, REDIS_URL: authenticatedRedisUrl(options.redisUrl, options.redisUsername, runtime.redisPassword), DOGE_BLOCK_SENDER_URL: options.senderPublicUrl, DOGE_BLOCK_SENDER_TOKEN: runtime.senderToken, SP1_GEN_PROOF_PATH: options.genProofBin, SP1_BLOCK_ELF_PATH: options.blockElf, SP1_BLOCK_VK_HASH: TESTNET_BLOCK_VK, DOGE_BLOCK_EVIDENCE_DIR: options.evidenceDir, DOGE_REDIS_SEED: String(options.redisSeed), DOGE_START_HEIGHT: String(runtime.startHeight), DOGE_CUSTODY_SCRIPT_CONFIG: pubkeyHex(BRIDGE_STATE_PDA), DOGE_RECIPIENT_ATAS: options.recipientAtas.map(pubkeyHex).join(","), DOGE_REQUIRED_CONFIRMATIONS: "1", DOGE_BRIDGE_CONFIG: runtime.configParams, DOGE_INITIAL_HEADER: runtime.initialHeader, SOLANA_RPC_URL: options.rpcUrl, DOGE_OPERATOR_KEYPAIR: options.operatorKeypair, DOGE_PAYER_KEYPAIR: options.payerKeypair, DOGE_MINT: options.dogeMint, DOGE_BRIDGE_PROGRAM: DOGE_BRIDGE_PROGRAM, PENDING_MINT_BUFFER_PROGRAM: PENDING_MINT_PROGRAM, TXO_BUFFER_PROGRAM: TXO_BUFFER_PROGRAM },
    };
    const daemon: ProcessSpec = {
        role: "daemon",
        command: [options.cliBin, "--network", "devnet", "daemon", "--operator-keypair", options.operatorKeypair, "--payer-keypair", options.payerKeypair, "--operator-store", options.operatorStore, "--manager-service-url", options.managerUrl, "--solana-rpc-url", options.rpcUrl, "--electrs-url", options.electrsUrl, "--manager-set-index", "1", "--wormhole-core-program", OFFICIAL_WORMHOLE_CORE, "--wormhole-shim-program", OFFICIAL_WORMHOLE_SHIM],
        cwd: path.dirname(options.cliBin),
    };
    return { sender, ibc, daemon };
}

async function waitFor(condition: () => Promise<boolean>, label: string, timeoutMs: number): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) { if (await condition()) return; await Bun.sleep(250); }
    fail(`Timed out waiting for ${label}`);
}
async function portOpen(port: number): Promise<boolean> {
    const { promise, resolve } = Promise.withResolvers<boolean>();
    const socket = net.connect({ host: "127.0.0.1", port });
    let settled = false;
    const finish = (value: boolean): void => { if (settled) return; settled = true; socket.destroy(); resolve(value); };
    socket.setTimeout(500); socket.once("connect", () => finish(true)); socket.once("timeout", () => finish(false)); socket.once("error", () => finish(false));
    return await promise;
}
function spawn(spec: ProcessSpec, stateDir: string): RunningProcess {
    const stdoutLog = path.join(stateDir, `${spec.role}.stdout.log`);
    const stderrLog = path.join(stateDir, `${spec.role}.stderr.log`);
    fs.writeFileSync(stdoutLog, "", { mode: 0o600 }); fs.writeFileSync(stderrLog, "", { mode: 0o600 });
    const child = Bun.spawn(spec.command, { cwd: spec.cwd, env: { ...process.env, ...spec.env }, detached: true, stdout: Bun.file(stdoutLog), stderr: Bun.file(stderrLog) });
    return { role: spec.role, child, stdoutLog, stderrLog };
}
async function stop(service: RunningProcess): Promise<void> {
    if (service.child.exitCode !== null) return;
    try { process.kill(-service.child.pid, "SIGTERM"); } catch { service.child.kill("SIGTERM"); }
    const exited = await Promise.race([service.child.exited.then(() => true), Bun.sleep(10_000).then(() => false)]);
    if (!exited && service.child.exitCode === null) { try { process.kill(-service.child.pid, "SIGKILL"); } catch { service.child.kill("SIGKILL"); } await service.child.exited; }
}
async function waitForLog(service: RunningProcess, pattern: RegExp, timeoutMs: number): Promise<void> {
    await waitFor(async () => {
        if (service.child.exitCode !== null) fail(`${service.role} exited with code ${service.child.exitCode}; see ${service.stderrLog}`);
        return pattern.test(`${fs.readFileSync(service.stdoutLog, "utf8")}\n${fs.readFileSync(service.stderrLog, "utf8")}`);
    }, `${service.role} readiness`, timeoutMs);
}

async function main(): Promise<void> {
    const options = resolveOptions();
    if (!options) return;
    const runtime = await preflight(options);
    const plans = processSpecs(options, runtime);
    console.log("\n[service plan]");
    for (const spec of [plans.sender, plans.ibc, plans.daemon]) console.log(`  (${spec.role}) ${commandText(spec.command)}`);
    if (options.dryRun) { console.log("\n[preflight] PASS — no process started."); return; }
    if (await portOpen(options.senderListenPort)) fail(`Sender port ${options.senderListenPort} is already in use`);
    fs.mkdirSync(options.stateDir, { recursive: true, mode: 0o700 }); fs.mkdirSync(options.evidenceDir, { recursive: true, mode: 0o700 }); fs.mkdirSync(path.dirname(options.operatorStore), { recursive: true, mode: 0o700 });
    const running: RunningProcess[] = [];
    let stopping = false;
    const shutdown = async (): Promise<void> => { if (stopping) return; stopping = true; for (const service of [...running].reverse()) await stop(service); };
    const shutdownPromise = Promise.withResolvers<void>();
    process.once("SIGINT", () => { void shutdown().finally(shutdownPromise.resolve); });
    process.once("SIGTERM", () => { void shutdown().finally(shutdownPromise.resolve); });
    try {
        const sender = spawn(plans.sender, options.stateDir); running.push(sender);
        await waitFor(async () => {
            if (sender.child.exitCode !== null) fail(`Sender exited with code ${sender.child.exitCode}; see ${sender.stderrLog}`);
            try { const response = await fetch(`http://127.0.0.1:${options.senderListenPort}/api/v1/health`, { headers: { authorization: `Bearer ${runtime.senderToken}` }, signal: AbortSignal.timeout(1_000) }); return response.ok; } catch { return false; }
        }, "block sender health", 30_000);
        console.log(`[ready:sender] http://127.0.0.1:${options.senderListenPort}/api/v1/health`);
        const ibc = spawn(plans.ibc, options.stateDir); running.push(ibc); await waitForLog(ibc, /block pipeline started:/, 60_000); console.log(`[ready:ibc] pid=${ibc.child.pid}`);
        const daemon = spawn(plans.daemon, options.stateDir); running.push(daemon); await waitForLog(daemon, /operator-daemon started:/, 30_000); console.log(`[ready:daemon] pid=${daemon.child.pid}`);
        console.log("[ready] Sender, IBC/SP1, and withdrawal daemon are running against devnet. Press Ctrl+C to stop them.");
        const unexpectedExit = Promise.race(running.map((service) => service.child.exited.then((exitCode) => ({ service, exitCode }))));
        const outcome = await Promise.race([unexpectedExit.then((value) => ({ kind: "exit" as const, value })), shutdownPromise.promise.then(() => ({ kind: "signal" as const }))]);
        if (outcome.kind === "exit" && !stopping) fail(`${outcome.value.service.role} exited unexpectedly with code ${outcome.value.exitCode}; see ${outcome.value.service.stderrLog}`);
    } finally { await shutdown(); }
}

if (import.meta.main) main().catch((error) => { console.error(`[error] ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
