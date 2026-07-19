#!/usr/bin/env bun

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { Database } from "bun:sqlite";
import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    TransactionInstruction,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";
import bs58 from "bs58";

type JsonObject = Record<string, unknown>;
type CommandResult = { command: string[]; exitCode: number; stdout: string; stderr: string; durationMs: number };
type RunningCommand = { process: Bun.Subprocess; result: Promise<CommandResult> };
type FundingArtifact = {
    address: string;
    wif: string;
    txid: string;
    vout: number;
    value: number;
    blockHeight: number;
    confirmations: number;
    network: "regtest";
};
type BridgeOutput = {
    bridgeStatePda: string;
    dogeMint: string;
    operatorPubkey: string;
    payerPubkey: string;
    operatorKeypair: string;
    payerKeypair: string;
    operatorStore: string;
    userPubkey: string;
    userTokenAccount: string;
};
type BridgeProgress = {
    accountDataLength: number;
    tipHeight: number;
    finalizedHeight: number;
    autoClaimedDepositsNextIndex: number;
};
type TokenBalance = { amount: bigint; decimals: number; uiAmountString: string };
type Options = {
    dryRun: boolean;
};
type Evidence = {
    schema: string;
    startedAt: string;
    finishedAt?: string;
    completed: boolean;
    profile: "local";
    mode: "dry-plan" | "full-live-localhost";
    dogeNetwork: "regtest";
    withdrawalMode: {
        snapshotAuthorization: true;
        outputsOnlyUtx0: true;
        managerSigningEnabled: boolean;
        broadcastEnabled: boolean;
        managerQuorum: string;
        offChainConfirmation: true;
    };
    paths: JsonObject;
    phases: Record<string, JsonObject>;
    completion?: JsonObject;
    failure?: { message: string; stack?: string };
};
type CompletionValidation = {
    completedEligible: boolean;
    block: JsonObject;
    withdrawal: JsonObject;
    evidence: JsonObject;
    reasons: string[];
};

const CLI_REPO = path.resolve(import.meta.dir, "../..");
const SOURCE_PROJECTS_DIR = path.resolve(
    process.env.PSY_DOGE_PROJECTS_DIR || path.resolve(CLI_REPO, ".."),
);
const LOCAL_PORT_OFFSET = Number.parseInt(process.env.PSY_DOGE_LOCAL_PORT_OFFSET || "5000", 10);
if (!Number.isInteger(LOCAL_PORT_OFFSET) || LOCAL_PORT_OFFSET < 0 || LOCAL_PORT_OFFSET > 5_000) {
    throw new Error("PSY_DOGE_LOCAL_PORT_OFFSET must be an integer from 0 through 5000");
}
const localPort = (base: number): number => base + LOCAL_PORT_OFFSET;
const SMOKE_TMP_ROOT = path.resolve(process.env.PSY_DOGE_LOCAL_TMP || "/tmp/psy-doge-local-validation");
const PROJECTS_DIR = path.join(SMOKE_TMP_ROOT, "projects");
const IBC_REPO = path.join(PROJECTS_DIR, "solana-doge-ibc");
const BRIDGE_REPO = path.join(PROJECTS_DIR, "psy-doge-solana-bridge");
const SENDER_REPO = path.join(PROJECTS_DIR, "solana-doge-bridge-block-sender");
const SP1_REPO = path.join(PROJECTS_DIR, "psy-bridge-sp1");
const LOCAL_OPS_ROOT = path.join(CLI_REPO, "doge");
const CLI_BIN = path.join(LOCAL_OPS_ROOT, "target/release/doge-solana-cli");
const LOCAL_LAUNCHER = path.join(import.meta.dir, "launcher.ts");
const DOGECOIN_REPO = path.join(PROJECTS_DIR, "dogecoin");
const ELECTRS_REPO = path.join(PROJECTS_DIR, "electrs-doge");
const DOGE_RPC_URL = `http://127.0.0.1:${localPort(22555)}`;
const ELECTRS_URL = `http://127.0.0.1:${localPort(3002)}`;
const SOLANA_RPC = `http://127.0.0.1:${localPort(8899)}`;
const MANAGER_SERVICE_URL = `http://127.0.0.1:${localPort(7071)}`;
const BRIDGE_OUTPUT_PATH = path.join(BRIDGE_REPO, "bridge-config/bridge-output.json");
const USER_OUTPUT_PATH = path.join(BRIDGE_REPO, "bridge-config/users/user1.json");
const KEYS_DIR = path.join(BRIDGE_REPO, "bridge-config/keys");
const EVIDENCE_PATH = path.join(SMOKE_TMP_ROOT, "evidence.json");
const DEPOSIT_EVIDENCE_PATH = path.join(SMOKE_TMP_ROOT, "deposit-evidence.json");
const WITHDRAWAL_EVIDENCE_PATH = path.join(SMOKE_TMP_ROOT, "withdrawal-evidence.json");
const FUNDING_ARTIFACT_PATH = path.join(SMOKE_TMP_ROOT, "funding.json");
const FUNDING_WIF_PATH = path.join(SMOKE_TMP_ROOT, "funding.wif");
const BLOCK_PROOF_EVIDENCE_ROOT = path.join(SMOKE_TMP_ROOT, "block-proof-evidence");
const BLOCK_PROOF_LATEST_PATH = path.join(BLOCK_PROOF_EVIDENCE_ROOT, "latest.json");
const DOGE_BRIDGE_PROGRAM = new PublicKey("DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ");
const LOCAL_NOOP_SHIM_PROGRAM = "FwDChsHWLwbhTiYQ4Sum5mjVWswECi9cmrA11GUFUuxi";
const DEPOSIT_AMOUNT_SATS = 100_000_000;
const DEPOSIT_FLAT_FEE_SATS = 10_000_000;
const DEPOSIT_FEE_NUM = 1;
const DEPOSIT_FEE_DEN = 100;
const EXPECTED_NET_MINT_SATS =
    DEPOSIT_AMOUNT_SATS - DEPOSIT_FLAT_FEE_SATS - Math.floor((DEPOSIT_AMOUNT_SATS * DEPOSIT_FEE_NUM) / DEPOSIT_FEE_DEN);
const BURN_AMOUNT_SATS = 50_000_000;
const WITHDRAWAL_FLAT_FEE_SATS = 10_000_000;
const WITHDRAWAL_FEE_NUM = 1;
const WITHDRAWAL_FEE_DEN = 100;
const EXPECTED_NET_WITHDRAWAL_SATS = calculateWithdrawalNetAmountSats(
    BURN_AMOUNT_SATS,
    WITHDRAWAL_FLAT_FEE_SATS,
    WITHDRAWAL_FEE_NUM,
    WITHDRAWAL_FEE_DEN,
);
const FUNDING_FEE_RESERVE_SATS = 1_000_000;
const FUNDING_ARTIFACT_SCHEMA = "psy-doge-local-smoke-funding-v1";
const FUNDING_MIN_CONFIRMATIONS = 100;
const PIPELINE_REQUIRED_CONFIRMATIONS = 1;
const DEPOSIT_PIPELINE_BLOCKS_TO_MINE = 1 + (2 * PIPELINE_REQUIRED_CONFIRMATIONS);
const INSTRUCTION_REQUEST_WITHDRAWAL = 2;
const REQUEST_WITHDRAWAL_INSTRUCTION_DATA_SIZE = 48;
const WITHDRAWAL_ADDRESS_TYPE_P2SH = 1;
const BRIDGE_TIP_HEIGHT_OFFSET = 68;
const BRIDGE_FINALIZED_HEIGHT_OFFSET = 268;
const BRIDGE_FINALIZED_AUTO_CLAIM_INDEX_OFFSET = 264;
const MAX_CAPTURE_CHARS = 16_384;
const GROTH16_PROOF_SIZE = 356;
const PUBLIC_VALUES_SIZE = 32;
const EXPECTED_BLOCK_VK_REGTEST = "0x002ed3c169b6415db45e569dd01675bfb2ba89c59c7d26582f3a22d2ec313ee8";
const MANAGER_QUORUM_M = 5;
const MANAGER_QUORUM_N = 7;

function usage(): string {
    return `Internal localhost validation runner

This file is not a public entrypoint. Use:
  doge-solana-cli --network localhost local-e2e

Internal options:
  --network localhost       Required
  --dry-run                 Non-destructive execution plan
  -h, --help                Show this help`;
}

function parseOptions(): Options | null {
    const { values } = parseArgs({
        args: Bun.argv.slice(2),
        strict: true,
        allowPositionals: false,
        options: {
            help: { type: "boolean", short: "h" },
            network: { type: "string" },
            "dry-run": { type: "boolean" },
        },
    });
    if (values.help) {
        console.log(usage());
        return null;
    }
    if (!values.network) throw new Error("--network localhost is required");
    if (values.network !== "localhost") throw new Error(`Local smoke only supports --network localhost; got '${values.network}'`);
    return {
        dryRun: Boolean(values["dry-run"]),
    };
}

function isObject(value: unknown): value is JsonObject {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertCondition(condition: unknown, message: string): asserts condition {
    if (!condition) throw new Error(message);
}

function requiredString(object: JsonObject, key: string, source: string): string {
    const value = object[key];
    if (typeof value !== "string" || value.length === 0) throw new Error(`${source} is missing non-empty string '${key}'`);
    return value;
}

function requiredNumber(object: JsonObject, key: string, source: string): number {
    const value = object[key];
    if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${source} is missing finite number '${key}'`);
    return value;
}

function optionalObject(object: JsonObject, key: string): JsonObject | null {
    const value = object[key];
    return isObject(value) ? value : null;
}

function readJsonObject(filePath: string): JsonObject {
    let parsed: unknown;
    try {
        parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    } catch (error) {
        throw new Error(`Cannot read JSON ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!isObject(parsed)) throw new Error(`${filePath} must contain a JSON object`);
    return parsed;
}

function calculateWithdrawalNetAmountSats(gross: number, flat: number, numerator: number, denominator: number): number {
    assertCondition(Number.isSafeInteger(gross) && gross > 0, `Invalid gross withdrawal amount ${gross}`);
    assertCondition(Number.isSafeInteger(flat) && flat >= 0, `Invalid withdrawal flat fee ${flat}`);
    assertCondition(Number.isSafeInteger(numerator) && numerator >= 0, `Invalid withdrawal fee numerator ${numerator}`);
    assertCondition(Number.isSafeInteger(denominator) && denominator > 0, `Invalid withdrawal fee denominator ${denominator}`);
    const grossBig = BigInt(gross);
    const fee = BigInt(flat) + ((grossBig * BigInt(numerator)) / BigInt(denominator));
    assertCondition(fee > 0n && fee < grossBig, `Withdrawal fee ${fee} must leave a positive net amount`);
    return Number(grossBig - fee);
}



function normalizeVk(value: string): string {
    const normalized = value.trim().toLowerCase();
    return normalized.startsWith("0x") ? normalized : `0x${normalized}`;
}

function sha256Hex(bytes: Uint8Array | Buffer | string): string {
    return createHash("sha256").update(bytes).digest("hex");
}

function fileSha256Hex(filePath: string): string {
    return sha256Hex(fs.readFileSync(filePath));
}

function isHex(value: unknown, bytes?: number): value is string {
    return typeof value === "string" && /^[0-9a-f]+$/i.test(value) && value.length % 2 === 0 && (bytes === undefined || value.length === bytes * 2);
}

function writeEvidence(evidence: Evidence): void {
    const temporary = `${EVIDENCE_PATH}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, EVIDENCE_PATH);
}

function compactOutput(value: string): string {
    if (value.length <= MAX_CAPTURE_CHARS) return value;
    return `${value.slice(0, MAX_CAPTURE_CHARS)}\n...[truncated ${value.length - MAX_CAPTURE_CHARS} chars]`;
}

function shellQuote(value: string): string {
    return /^[A-Za-z0-9_./:=,@+-]+$/.test(value) ? value : JSON.stringify(value);
}


function commandEvidence(result: CommandResult): JsonObject {
    return {
        command: result.command,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        stdout: compactOutput(result.stdout),
        stderr: compactOutput(result.stderr),
    };
}

async function readStream(stream: ReadableStream<Uint8Array> | null): Promise<string> {
    return stream ? await new Response(stream).text() : "";
}

function startCommand(bin: string, args: string[], options: { cwd?: string; env?: Record<string, string> } = {}): RunningCommand {
    const command = [bin, ...args];
    console.log(`$ ${command.map(shellQuote).join(" ")}`);
    const started = Date.now();
    const child = Bun.spawn(command, {
        cwd: options.cwd ?? CLI_REPO,
        env: { ...process.env, NO_PROXY: "localhost,127.0.0.1", no_proxy: "localhost,127.0.0.1", ...options.env },
        stdout: "pipe",
        stderr: "pipe",
    });
    const result = (async (): Promise<CommandResult> => {
        const [stdout, stderr, exitCode] = await Promise.all([readStream(child.stdout), readStream(child.stderr), child.exited]);
        const completed = { command, exitCode, stdout, stderr, durationMs: Date.now() - started };
        if (stdout.trim()) console.log(stdout.trim());
        if (stderr.trim()) console.error(stderr.trim());
        if (exitCode !== 0) {
            throw new Error(`Command failed with exit code ${exitCode}: ${command.map(shellQuote).join(" ")}\n${stderr || stdout}`);
        }
        return completed;
    })();
    return { process: child, result };
}

async function stopCommand(command: RunningCommand | null): Promise<void> {
    if (!command) return;
    if (command.process.exitCode === null) {
        command.process.kill("SIGTERM");
        const exited = await Promise.race([
            command.process.exited.then(() => true),
            Bun.sleep(5_000).then(() => false),
        ]);
        if (!exited && command.process.exitCode === null) {
            command.process.kill("SIGKILL");
            await command.process.exited;
        }
    }
    await command.result.catch(() => undefined);
}

async function runCommand(bin: string, args: string[], options: { cwd?: string; env?: Record<string, string> } = {}): Promise<CommandResult> {
    return await startCommand(bin, args, options).result;
}

async function waitFor<T>(description: string, timeoutMs: number, condition: () => Promise<T | null | undefined | false>, intervalMs = 1_000): Promise<T> {
    const started = Date.now();
    let lastError: unknown;
    while (Date.now() - started < timeoutMs) {
        try {
            const value = await condition();
            if (value !== null && value !== undefined && value !== false) return value;
        } catch (error) {
            lastError = error;
        }
        await Bun.sleep(intervalMs);
    }
    const suffix = lastError instanceof Error ? ` Last error: ${lastError.message}` : "";
    throw new Error(`Timed out after ${timeoutMs} ms waiting for ${description}.${suffix}`);
}

async function waitForArtifactWhileRunning<T>(
    command: RunningCommand,
    description: string,
    timeoutMs: number,
    condition: () => Promise<T | null | undefined | false>,
): Promise<T> {
    return await Promise.race([
        waitFor(description, timeoutMs, condition),
        command.process.exited.then(async (exitCode) => {
            const finalValue = await condition();
            if (finalValue !== null && finalValue !== undefined && finalValue !== false) return finalValue;
            throw new Error(`Command exited with code ${exitCode} before ${description}`);
        }),
    ]);
}

async function jsonRpc(url: string, method: string, params: unknown[], auth?: { user: string; password: string }): Promise<unknown> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (auth) headers.authorization = `Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}`;
    const response = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify({ jsonrpc: "2.0", id: `${method}-${Date.now()}`, method, params }),
    });
    const text = await response.text();
    let body: unknown;
    try { body = JSON.parse(text); } catch { throw new Error(`${method} returned invalid JSON: ${text}`); }
    if (!response.ok) throw new Error(`${method} returned HTTP ${response.status}: ${text}`);
    if (!isObject(body)) throw new Error(`${method} returned a non-object JSON-RPC response`);
    if (body.error !== null && body.error !== undefined) throw new Error(`${method} JSON-RPC error: ${JSON.stringify(body.error)}`);
    if (!("result" in body)) throw new Error(`${method} JSON-RPC response has no result`);
    return body.result;
}

async function dogeRpc(method: string, params: unknown[] = []): Promise<unknown> {
    return await jsonRpc(DOGE_RPC_URL, method, params, { user: "doge", password: "doge" });
}

async function solanaRpc(method: string, params: unknown[] = []): Promise<unknown> {
    return await jsonRpc(SOLANA_RPC, method, params);
}

async function electrsGet(route: string): Promise<unknown> {
    const url = `${ELECTRS_URL}${route.startsWith("/") ? route : `/${route}`}`;
    const response = await fetch(url);
    const text = await response.text();
    if (!response.ok) throw new Error(`Electrs GET ${url} returned ${response.status}: ${text}`);
    try { return JSON.parse(text); } catch { return text; }
}

function prepareIsolatedProjects(): void {
    const isWithin = (parent: string, candidate: string): boolean => {
        const relative = path.relative(parent, candidate);
        return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
    };
    if (SMOKE_TMP_ROOT === "/" || isWithin(CLI_REPO, SMOKE_TMP_ROOT) || isWithin(SOURCE_PROJECTS_DIR, SMOKE_TMP_ROOT)) {
        throw new Error(`Unsafe local validation directory: ${SMOKE_TMP_ROOT}`);
    }
    fs.rmSync(SMOKE_TMP_ROOT, { recursive: true, force: true });
    fs.mkdirSync(PROJECTS_DIR, { recursive: true, mode: 0o700 });

    for (const name of [
        "dogecoin",
        "electrs-doge",
        "solana-doge-ibc",
        "psy-bridge-sp1",
        "solana-doge-bridge-block-sender",
    ]) {
        const source = path.join(SOURCE_PROJECTS_DIR, name);
        assertCondition(fs.existsSync(source), `Missing sibling repository: ${source}`);
        fs.symlinkSync(fs.realpathSync(source), path.join(PROJECTS_DIR, name), "dir");
    }

    const sourceBridge = path.join(SOURCE_PROJECTS_DIR, "psy-doge-solana-bridge");
    assertCondition(fs.existsSync(sourceBridge), `Missing bridge repository: ${sourceBridge}`);
    fs.mkdirSync(BRIDGE_REPO, { mode: 0o700 });
    for (const entry of fs.readdirSync(sourceBridge, { withFileTypes: true })) {
        if (entry.name === ".git" || entry.name === "bridge-config") continue;
        fs.symlinkSync(
            path.join(fs.realpathSync(sourceBridge), entry.name),
            path.join(BRIDGE_REPO, entry.name),
            entry.isDirectory() ? "dir" : "file",
        );
    }
    const bridgeConfig = path.join(BRIDGE_REPO, "bridge-config");
    fs.mkdirSync(bridgeConfig, { mode: 0o700 });
    const sourceDogeConfig = path.join(sourceBridge, "bridge-config/doge_config.json");
    assertCondition(fs.existsSync(sourceDogeConfig), `Missing bridge initialization template: ${sourceDogeConfig}`);
    fs.copyFileSync(sourceDogeConfig, path.join(bridgeConfig, "doge_config.json"));
}

function executable(candidates: Array<string | undefined>): string | null {
    for (const candidate of candidates) {
        if (!candidate) continue;
        const resolved = candidate.includes(path.sep) ? path.resolve(candidate) : Bun.which(candidate);
        if (!resolved) continue;
        try { fs.accessSync(resolved, fs.constants.X_OK); return resolved; } catch { /* next */ }
    }
    return null;
}


function preflightLocalBinaries(): JsonObject {
    assertCondition(fs.existsSync(CLI_BIN), `Required release CLI is missing: ${CLI_BIN}`);
    fs.accessSync(CLI_BIN, fs.constants.X_OK);
    const dogecoind = executable([process.env.DOGECOIND, "dogecoind", "/tmp/real-dogecoind", path.join(DOGECOIN_REPO, "src/dogecoind"), path.join(DOGECOIN_REPO, "build/src/dogecoind")]);
    const dogecoinCli = executable([process.env.DOGECOIN_CLI, "dogecoin-cli", "/tmp/real-dogecoin-cli", path.join(DOGECOIN_REPO, "src/dogecoin-cli"), path.join(DOGECOIN_REPO, "build/src/dogecoin-cli")]);
    const electrs = executable([process.env.ELECTRS_DOGE, "electrs-doge", path.join(ELECTRS_REPO, "target/release/electrs")]);
    const missing = [dogecoind ? null : "dogecoind", dogecoinCli ? null : "dogecoin-cli", electrs ? null : "electrs-doge"].filter(Boolean);
    assertCondition(missing.length === 0, `Local validation is missing release binaries: ${missing.join(", ")}`);
    return { mode: "regtest", cli: CLI_BIN, dogecoind, dogecoinCli, electrs };
}

function launcherCommand(_options: Options): string[] {
    return [
        "bun", LOCAL_LAUNCHER,
        "--network", "localhost",
        "--projects-dir", PROJECTS_DIR,
        "--initialize",
        "--create-users",
        "--dogecoind",
        "--prepare-local-smoke-funding", FUNDING_ARTIFACT_PATH,
        "--block-sender",
        "--ibc-pipeline",
        "--manager-service",
        "--rebuild-programs",
    ];
}

async function startLauncher(options: Options): Promise<{ process: Bun.Subprocess; stdoutLog: string; stderrLog: string }> {
    const command = launcherCommand(options);
    console.log(`$ ${command.map(shellQuote).join(" ")}`);
    const stdoutLog = path.join(SMOKE_TMP_ROOT, "launcher.stdout.log");
    const stderrLog = path.join(SMOKE_TMP_ROOT, "launcher.stderr.log");
    fs.mkdirSync(SMOKE_TMP_ROOT, { recursive: true, mode: 0o700 });
    fs.writeFileSync(stdoutLog, "", { mode: 0o600 });
    fs.writeFileSync(stderrLog, "", { mode: 0o600 });
    const binaries = preflightLocalBinaries();
    const environment: Record<string, string> = {
        ...process.env as Record<string, string>,
        NO_PROXY: "localhost,127.0.0.1",
        no_proxy: "localhost,127.0.0.1",
        XDG_STATE_HOME: path.join(SMOKE_TMP_ROOT, "state"),
        PSY_DOGE_LOCAL_PORT_OFFSET: String(LOCAL_PORT_OFFSET),
        DOGE_BLOCK_EVIDENCE_DIR: BLOCK_PROOF_EVIDENCE_ROOT,
        DOGECOIND: String(binaries.dogecoind),
        DOGECOIN_CLI: String(binaries.dogecoinCli),
        ELECTRS_DOGE: String(binaries.electrs),
    };
    const child = Bun.spawn(command, {
        cwd: CLI_REPO,
        env: environment,
        stdout: Bun.file(stdoutLog),
        stderr: Bun.file(stderrLog),
    });
    return { process: child, stdoutLog, stderrLog };
}

async function stopLauncher(launcher: Bun.Subprocess): Promise<JsonObject> {
    if (launcher.exitCode === null) launcher.kill("SIGTERM");
    const exitCode = await Promise.race([launcher.exited, Bun.sleep(15_000).then(() => null)]);
    if (exitCode === null) {
        launcher.kill("SIGKILL");
        return { keptRunning: false, pid: launcher.pid, exitCode: await launcher.exited, forced: true };
    }
    return { keptRunning: false, pid: launcher.pid, exitCode, forced: false };
}

function readLocalFunding(filePath: string): FundingArtifact {
    const mode = fs.statSync(filePath).mode & 0o777;
    assertCondition(mode === 0o600, `${filePath} must have mode 600, got ${mode.toString(8)}`);
    const artifact = readJsonObject(filePath);
    assertCondition(requiredString(artifact, "schema", filePath) === FUNDING_ARTIFACT_SCHEMA, `${filePath} schema mismatch`);
    assertCondition(requiredString(artifact, "network", filePath) === "regtest", `${filePath} must target regtest`);
    const address = requiredString(artifact, "address", filePath);
    const wif = requiredString(artifact, "wif", filePath);
    const txid = requiredString(artifact, "txid", filePath);
    const vout = requiredNumber(artifact, "vout", filePath);
    const value = requiredNumber(artifact, "value", filePath);
    const blockHeight = requiredNumber(artifact, "blockHeight", filePath);
    const confirmations = requiredNumber(artifact, "confirmations", filePath);
    assertCondition(isHex(txid, 32), `${filePath}.txid must be 32-byte hex`);
    assertCondition(Number.isSafeInteger(vout) && vout >= 0, `${filePath}.vout invalid`);
    assertCondition(Number.isSafeInteger(value) && value >= DEPOSIT_AMOUNT_SATS + FUNDING_FEE_RESERVE_SATS, `${filePath}.value insufficient`);
    assertCondition(confirmations >= FUNDING_MIN_CONFIRMATIONS, `${filePath}.confirmations must be >= ${FUNDING_MIN_CONFIRMATIONS}`);
    return { address, wif, txid, vout, value, blockHeight, confirmations, network: "regtest" };
}


function loadBridgeOutput(): BridgeOutput {
    const bridge = readJsonObject(BRIDGE_OUTPUT_PATH);
    const user = readJsonObject(USER_OUTPUT_PATH);
    const output: BridgeOutput = {
        bridgeStatePda: requiredString(bridge, "bridge_state_pda", BRIDGE_OUTPUT_PATH),
        dogeMint: requiredString(bridge, "doge_mint", BRIDGE_OUTPUT_PATH),
        operatorPubkey: requiredString(bridge, "operator_pubkey", BRIDGE_OUTPUT_PATH),
        payerPubkey: requiredString(bridge, "payer_pubkey", BRIDGE_OUTPUT_PATH),
        operatorKeypair: path.join(KEYS_DIR, "operator.json"),
        payerKeypair: path.join(KEYS_DIR, "payer.json"),
        operatorStore: path.join(KEYS_DIR, "operator-store.sqlite"),
        userPubkey: requiredString(user, "pubkey", USER_OUTPUT_PATH),
        userTokenAccount: requiredString(user, "doge_ata", USER_OUTPUT_PATH),
    };
    for (const keyPath of [output.operatorKeypair, output.payerKeypair]) assertCondition(fs.existsSync(keyPath), `Missing keypair file: ${keyPath}`);
    return output;
}

function loadSolanaKeypair(filePath: string, field?: string): Keypair {
    const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
    const value = field && isObject(parsed) ? parsed[field] : parsed;
    if (!Array.isArray(value) || value.length !== 64 || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
        throw new Error(`${filePath} must contain a 64-byte Solana keypair`);
    }
    return Keypair.fromSecretKey(Uint8Array.from(value));
}

function getAccountBytes(result: unknown, address: string): Uint8Array {
    if (!isObject(result) || !isObject(result.value)) throw new Error(`Solana account ${address} is absent`);
    const data = result.value.data;
    if (!Array.isArray(data) || typeof data[0] !== "string" || data[1] !== "base64") throw new Error(`Invalid account data for ${address}`);
    return Uint8Array.from(Buffer.from(data[0], "base64"));
}

async function readBridgeProgress(bridgeStatePda: string): Promise<BridgeProgress> {
    const bytes = getAccountBytes(await solanaRpc("getAccountInfo", [bridgeStatePda, { encoding: "base64", commitment: "confirmed" }]), bridgeStatePda);
    assertCondition(bytes.length > BRIDGE_FINALIZED_HEIGHT_OFFSET + 4, `Bridge state account is too short: ${bytes.length}`);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return {
        accountDataLength: bytes.length,
        tipHeight: view.getUint32(BRIDGE_TIP_HEIGHT_OFFSET, true),
        finalizedHeight: view.getUint32(BRIDGE_FINALIZED_HEIGHT_OFFSET, true),
        autoClaimedDepositsNextIndex: view.getUint32(BRIDGE_FINALIZED_AUTO_CLAIM_INDEX_OFFSET, true),
    };
}

async function tokenBalance(tokenAccount: string): Promise<TokenBalance> {
    const result = await solanaRpc("getTokenAccountBalance", [tokenAccount, { commitment: "confirmed" }]);
    if (!isObject(result) || !isObject(result.value)) throw new Error(`Invalid token balance response for ${tokenAccount}`);
    const amount = requiredString(result.value, "amount", "getTokenAccountBalance.value");
    return {
        amount: BigInt(amount),
        decimals: requiredNumber(result.value, "decimals", "getTokenAccountBalance.value"),
        uiAmountString: requiredString(result.value, "uiAmountString", "getTokenAccountBalance.value"),
    };
}

function p2shPayload(address: string): Uint8Array {
    const decoded = Uint8Array.from(bs58.decode(address));
    assertCondition(decoded.length === 25 && decoded[0] === 0xc4, `${address} is not a shared regtest/testnet P2SH address`);
    const body = decoded.slice(0, 21);
    const checksum = decoded.slice(21);
    const expected = createHash("sha256").update(createHash("sha256").update(body).digest()).digest().subarray(0, 4);
    assertCondition(Buffer.from(checksum).equals(expected), `${address} has an invalid checksum`);
    return decoded.slice(1, 21);
}

function p2shAddress(payload: Uint8Array): string {
    assertCondition(payload.length === 20, `P2SH payload must be 20 bytes`);
    const body = Buffer.concat([Buffer.from([0xc4]), Buffer.from(payload)]);
    const checksum = createHash("sha256").update(createHash("sha256").update(body).digest()).digest().subarray(0, 4);
    return bs58.encode(Buffer.concat([body, checksum]));
}

function buildRequestWithdrawalInstructionData(recipientPayload: Uint8Array, gross: bigint, net: bigint): Buffer {
    assertCondition(recipientPayload.length === 20, `P2SH payload must be 20 bytes`);
    assertCondition(gross > 0n && net > 0n && net < gross, `Invalid withdrawal gross/net amount`);
    const data = Buffer.alloc(REQUEST_WITHDRAWAL_INSTRUCTION_DATA_SIZE);
    data.fill(INSTRUCTION_REQUEST_WITHDRAWAL, 0, 8);
    data.writeBigUInt64LE(gross, 8);
    data.writeUInt32LE(WITHDRAWAL_ADDRESS_TYPE_P2SH, 16);
    data.set(recipientPayload, 20);
    data.writeBigUInt64LE(net, 40);
    return data;
}

async function requestWithdrawal(
    payer: Keypair,
    user: Keypair,
    userTokenAccount: string,
    dogeMint: string,
    recipientAddress: string,
): Promise<string> {
    const bridgeState = PublicKey.findProgramAddressSync([Buffer.from("bridge_state")], DOGE_BRIDGE_PROGRAM)[0];
    const instruction = new TransactionInstruction({
        programId: DOGE_BRIDGE_PROGRAM,
        keys: [
            { pubkey: bridgeState, isSigner: false, isWritable: true },
            { pubkey: new PublicKey(userTokenAccount), isSigner: false, isWritable: true },
            { pubkey: new PublicKey(dogeMint), isSigner: false, isWritable: true },
            { pubkey: user.publicKey, isSigner: true, isWritable: false },
            { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        ],
        data: buildRequestWithdrawalInstructionData(p2shPayload(recipientAddress), BigInt(BURN_AMOUNT_SATS), BigInt(EXPECTED_NET_WITHDRAWAL_SATS)),
    });
    const connection = new Connection(SOLANA_RPC, "confirmed");
    const latest = await connection.getLatestBlockhash("confirmed");
    const transaction = new Transaction({ feePayer: payer.publicKey, recentBlockhash: latest.blockhash }).add(instruction);
    transaction.sign(payer, user);
    const signature = await connection.sendRawTransaction(transaction.serialize(), { skipPreflight: false, maxRetries: 5 });
    await connection.confirmTransaction({ signature, ...latest }, "confirmed");
    return signature;
}

function depositArgs(bridge: BridgeOutput, funding: FundingArtifact): string[] {
    fs.writeFileSync(FUNDING_WIF_PATH, `${funding.wif}\n`, { mode: 0o600 });
    return [
        "--network", "localhost",
        "deposit",
        "--manager-set-index", "0",
        "--solana-rpc-url", SOLANA_RPC,
        "--operator-keypair", bridge.operatorKeypair,
        "--payer-keypair", bridge.payerKeypair,
        "--recipient-token-account", bridge.userTokenAccount,
        "--operator-store", bridge.operatorStore,
        "--electrs-url", ELECTRS_URL,
        "--wormhole-core-program", LOCAL_NOOP_SHIM_PROGRAM,
        "--wormhole-shim-program", LOCAL_NOOP_SHIM_PROGRAM,
        "--funding-wif-file", FUNDING_WIF_PATH,
        "--funding-txid", funding.txid,
        "--funding-vout", String(funding.vout),
        "--funding-amount", String(funding.value),
        "--amount-sats", String(DEPOSIT_AMOUNT_SATS),
        "--confirmation-timeout-secs", "180",
        "--poll-interval-ms", "500",
        "--evidence-path", DEPOSIT_EVIDENCE_PATH,
    ];
}

function withdrawalArgs(bridge: BridgeOutput, resume = false): string[] {
    const args = [
        "--network", "localhost",
        "withdraw",
        "--solana-rpc-url", SOLANA_RPC,
        "--operator-keypair", bridge.operatorKeypair,
        "--payer-keypair", bridge.payerKeypair,
        "--operator-store", bridge.operatorStore,
        "--manager-service-url", MANAGER_SERVICE_URL,
        "--electrs-url", ELECTRS_URL,
        "--wormhole-core-program", LOCAL_NOOP_SHIM_PROGRAM,
        "--wormhole-shim-program", LOCAL_NOOP_SHIM_PROGRAM,
        "--evidence-path", WITHDRAWAL_EVIDENCE_PATH,
        "--manager-set-index", "0",
        "--manager-signing-enabled",
        "--broadcast-enabled",
        "--signing-timeout-secs", "180",
        "--poll-interval-ms", "500",
    ];
    if (resume) args.push("--resume");
    return args;
}

async function mineBlocks(count: number, address: string): Promise<{ before: number; after: number; hashes: string[] }> {
    const beforeRaw = await dogeRpc("getblockcount");
    assertCondition(typeof beforeRaw === "number", `getblockcount returned ${String(beforeRaw)}`);
    const generated = await dogeRpc("generatetoaddress", [count, address]);
    assertCondition(Array.isArray(generated) && generated.length === count, `generatetoaddress did not return ${count} hashes`);
    const after = beforeRaw + count;
    await waitFor(`Electrs indexing height ${after}`, 120_000, async () => {
        const tip = await electrsGet("/blocks/tip/height");
        return Number(tip) >= after ? true : false;
    }, 500);
    return { before: beforeRaw, after, hashes: generated.map(String) };
}

function reverseHex(hex: string): string {
    const bytes = Buffer.from(hex, "hex");
    bytes.reverse();
    return bytes.toString("hex");
}

function readOperatorStoreEvidence(storePath: string, snapshotSignature: string): JsonObject {
    assertCondition(fs.existsSync(storePath), `OperatorStore missing: ${storePath}`);
    const database = new Database(storePath, { readonly: true });
    try {
        const graph = database.query(`
            SELECT sb.solana_signature AS snapshot_signature,
                   sb.status AS snapshot_status,
                   sb.request_start_index AS request_start,
                   sb.request_end_index AS request_end,
                   hex(sb.snapshot_root) AS snapshot_root_hex,
                   hex(sb.payload_hash) AS payload_hash_hex,
                   sb.wormhole_sequence AS wormhole_sequence,
                   pw.status AS process_status,
                   hex(dt.txid) AS txid_internal_hex,
                   dt.status AS dogecoin_status,
                   hex(dt.block_hash) AS block_hash_hex,
                   dt.block_height AS block_height,
                   dt.confirmations AS confirmations,
                   cr.reservation_id AS reservation_id,
                   cr.status AS reservation_status,
                   hex(cr.spend_txid) AS reservation_spend_txid_internal_hex
              FROM snapshot_batches sb
              JOIN process_withdrawals pw ON pw.solana_signature = sb.solana_signature
              JOIN dogecoin_transactions dt ON dt.raw_hash = pw.dogecoin_raw_hash
              JOIN custody_reservations cr ON cr.reservation_id = sb.reservation_id
             WHERE sb.solana_signature = ?1
        `).get(snapshotSignature) as JsonObject | null;
        assertCondition(graph, `OperatorStore has no complete graph for snapshot ${snapshotSignature}`);
        const requestRows = database.query(`
            SELECT request_index, status FROM withdrawal_requests
             WHERE request_index >= ?1 AND request_index < ?2 ORDER BY request_index
        `).all(Number(graph.request_start), Number(graph.request_end)) as JsonObject[];
        const inputRows = database.query(`
            SELECT vout, status, hex(spend_txid) AS spend_txid_internal_hex
              FROM custody_utxos WHERE reservation_id = ?1 ORDER BY leaf_index, txid, vout
        `).all(String(graph.reservation_id)) as JsonObject[];
        const txidInternal = requiredString(graph, "txid_internal_hex", "OperatorStore.graph").toLowerCase();
        return {
            schema: "doge-operator-store-confirmed-snapshot-v1",
            snapshotSignature: requiredString(graph, "snapshot_signature", "OperatorStore.graph"),
            snapshotStatus: requiredString(graph, "snapshot_status", "OperatorStore.graph"),
            requestStart: requiredNumber(graph, "request_start", "OperatorStore.graph"),
            requestEnd: requiredNumber(graph, "request_end", "OperatorStore.graph"),
            snapshotRootHex: requiredString(graph, "snapshot_root_hex", "OperatorStore.graph").toLowerCase(),
            payloadHashHex: requiredString(graph, "payload_hash_hex", "OperatorStore.graph").toLowerCase(),
            wormholeSequence: requiredNumber(graph, "wormhole_sequence", "OperatorStore.graph"),
            processStatus: requiredString(graph, "process_status", "OperatorStore.graph"),
            dogecoinStatus: requiredString(graph, "dogecoin_status", "OperatorStore.graph"),
            txidInternalHex: txidInternal,
            txid: reverseHex(txidInternal),
            blockHashInternalHex: requiredString(graph, "block_hash_hex", "OperatorStore.graph").toLowerCase(),
            blockHeight: requiredNumber(graph, "block_height", "OperatorStore.graph"),
            confirmations: requiredNumber(graph, "confirmations", "OperatorStore.graph"),
            reservationId: requiredString(graph, "reservation_id", "OperatorStore.graph"),
            reservationStatus: requiredString(graph, "reservation_status", "OperatorStore.graph"),
            reservationSpendTxidInternalHex: requiredString(graph, "reservation_spend_txid_internal_hex", "OperatorStore.graph").toLowerCase(),
            requests: requestRows.map((row) => ({ index: requiredNumber(row, "request_index", "OperatorStore.request"), status: requiredString(row, "status", "OperatorStore.request") })),
            inputs: inputRows.map((row) => ({ vout: requiredNumber(row, "vout", "OperatorStore.input"), status: requiredString(row, "status", "OperatorStore.input"), spendTxidInternalHex: requiredString(row, "spend_txid_internal_hex", "OperatorStore.input").toLowerCase() })),
        };
    } finally {
        database.close();
    }
}

function readArtifactEntry(artifacts: JsonObject, key: string, source: string): JsonObject {
    const entry = artifacts[key];
    if (!isObject(entry)) throw new Error(`${source}.artifacts.${key} must be an object`);
    return entry;
}

function validateBinaryArtifact(entry: JsonObject, source: string, expectedSize: number): { path: string; sha256: string; size: number; bytes: Uint8Array } {
    const artifactPath = requiredString(entry, "path", source);
    const declaredSha = requiredString(entry, "sha256", source).toLowerCase();
    const declaredSize = requiredNumber(entry, "size", source);
    assertCondition(fs.existsSync(artifactPath), `${source} missing: ${artifactPath}`);
    const bytes = new Uint8Array(fs.readFileSync(artifactPath));
    assertCondition(bytes.length === expectedSize && declaredSize === expectedSize, `${source} must be exactly ${expectedSize} bytes`);
    assertCondition(bytes.some((byte) => byte !== 0), `${source} must not be all zero`);
    const actualSha = sha256Hex(bytes);
    assertCondition(actualSha === declaredSha, `${source} sha256 mismatch`);
    return { path: artifactPath, sha256: actualSha, size: bytes.length, bytes };
}

export function validateBlockProofEvidence(
    manifest: JsonObject,
    options: { requireDeposit?: boolean; requireMinted?: boolean } = {},
): JsonObject {
    const source = "blockProof.latest";
    const requireDeposit = options.requireDeposit ?? true;
    const requireMinted = options.requireMinted ?? false;
    const height = requiredNumber(manifest, "height", source);
    const contentSha = requiredString(manifest, "content_sha256", source).toLowerCase();
    const evidenceDir = requiredString(manifest, "evidence_dir", source);
    assertCondition(evidenceDir.includes(`height-${height}`) && evidenceDir.toLowerCase().includes(contentSha), `${source}.evidence_dir is not content-addressed`);
    const artifacts = optionalObject(manifest, "artifacts");
    assertCondition(artifacts, `${source}.artifacts is required`);
    const proof = validateBinaryArtifact(readArtifactEntry(artifacts, "proof", source), `${source}.proof`, GROTH16_PROOF_SIZE);
    const publicValues = validateBinaryArtifact(readArtifactEntry(artifacts, "public_values", source), `${source}.public_values`, PUBLIC_VALUES_SIZE);
    const vk = validateBinaryArtifact(readArtifactEntry(artifacts, "vk", source), `${source}.vk`, 32);
    const vkFromFile = normalizeVk(Buffer.from(vk.bytes).toString("hex"));
    const manifestVk = normalizeVk(typeof manifest.vk_hash === "string" ? manifest.vk_hash : vkFromFile);
    assertCondition(manifestVk === EXPECTED_BLOCK_VK_REGTEST, `${source} VK ${manifestVk} does not match ${EXPECTED_BLOCK_VK_REGTEST}`);
    assertCondition(vkFromFile === EXPECTED_BLOCK_VK_REGTEST, `${source}.vk file does not match the regtest VK`);
    const elf = readArtifactEntry(artifacts, "elf", source);
    const elfPath = requiredString(elf, "path", `${source}.elf`);
    const elfSha = requiredString(elf, "sha256", `${source}.elf`).toLowerCase();
    assertCondition(fs.existsSync(elfPath) && fileSha256Hex(elfPath) === elfSha, `${source}.elf hash mismatch`);
    const inputs = readArtifactEntry(artifacts, "inputs", source);
    const inputsPath = requiredString(inputs, "path", `${source}.inputs`);
    const inputsSha = requiredString(inputs, "sha256", `${source}.inputs`).toLowerCase();
    assertCondition(fs.existsSync(inputsPath) && fileSha256Hex(inputsPath) === inputsSha, `${source}.inputs hash mismatch`);
    const depositCount = typeof manifest.deposit_count === "number" ? manifest.deposit_count : 0;
    const mintedAmountSats = typeof manifest.minted_amount_sats === "number" ? manifest.minted_amount_sats : 0;
    const witnessDepositCount = typeof manifest.witness_deposit_count === "number" ? manifest.witness_deposit_count : 0;
    const witnessMintedAmountSats = typeof manifest.witness_minted_amount_sats === "number" ? manifest.witness_minted_amount_sats : 0;
    if (requireDeposit) assertCondition((depositCount > 0 && mintedAmountSats > 0) || (witnessDepositCount > 0 && witnessMintedAmountSats > 0), `${source} contains no deposit transition`);
    const status = typeof manifest.status === "string" ? manifest.status : null;
    if (requireMinted) {
        assertCondition(status === "minted", `${source}.status must be minted`);
        assertCondition(manifest.buffer_upload_completed === true, `${source}.buffer_upload_completed must be true`);
        assertCondition(depositCount > 0 && mintedAmountSats > 0, `${source} finalized mint fields are missing`);
        assertCondition(Array.isArray(manifest.mint_group_signatures) && manifest.mint_group_signatures.length > 0, `${source}.mint_group_signatures is empty`);
        assertCondition(typeof manifest.mint_groups_processed === "number" && manifest.mint_groups_processed > 0, `${source}.mint_groups_processed must be positive`);
        assertCondition(manifest.total_mints_processed === depositCount, `${source}.total_mints_processed must equal deposit_count`);
    }
    return {
        height,
        status,
        contentSha256: contentSha,
        evidenceDir,
        manifestPath: typeof manifest.manifest_path === "string" ? manifest.manifest_path : null,
        manifestSha256: typeof manifest.manifest_sha256 === "string" ? manifest.manifest_sha256 : null,
        depositCount,
        mintedAmountSats,
        witnessDepositCount,
        witnessMintedAmountSats,
        proofPath: proof.path,
        proofBytes: proof.size,
        proofSha256Hex: proof.sha256,
        publicValuesPath: publicValues.path,
        publicValuesBytes: publicValues.size,
        publicValuesSha256Hex: publicValues.sha256,
        vkPath: vk.path,
        vkHash: manifestVk,
        elfPath,
        elfSha256Hex: elfSha,
        inputsPath,
        inputsSha256Hex: inputsSha,
        submissionSignature: requiredString(manifest, "submission_signature", source),
        verified: true,
    };
}

export function validateWithdrawalEvidence(
    evidence: JsonObject,
    options: { requireConfirmed?: boolean; operatorStore?: JsonObject } = {},
): JsonObject {
    const source = "withdrawalEvidence";
    const schema = requiredString(evidence, "schema", source);
    assertCondition(schema === "doge-process-withdrawal-v5-durable-snapshot", `${source}.schema unexpected: ${schema}`);
    const snapshot = optionalObject(evidence, "snapshot");
    const withdrawal = optionalObject(evidence, "withdrawal");
    const manager = optionalObject(evidence, "manager");
    const dogecoin = optionalObject(evidence, "dogecoin");
    const custody = optionalObject(evidence, "custody");
    assertCondition(snapshot && withdrawal && manager && dogecoin && custody, `${source} must contain snapshot/withdrawal/manager/dogecoin/custody`);

    const snapshotSignature = requiredString(snapshot, "signature", `${source}.snapshot`);
    const snapshotSlot = requiredNumber(snapshot, "slot", `${source}.snapshot`);
    const requestStart = requiredNumber(snapshot, "requestStart", `${source}.snapshot`);
    const requestEnd = requiredNumber(snapshot, "requestEnd", `${source}.snapshot`);
    assertCondition(Number.isSafeInteger(requestStart) && Number.isSafeInteger(requestEnd) && requestEnd > requestStart, `${source}.snapshot request range is invalid`);
    const snapshotRootHex = requiredString(snapshot, "snapshotRootHex", `${source}.snapshot`).toLowerCase();
    const sequence = requiredNumber(snapshot, "sequence", `${source}.snapshot`);
    const payloadHex = requiredString(snapshot, "payloadHex", `${source}.snapshot`).toLowerCase();
    assertCondition(snapshotSlot > 0, `${source}.snapshot.slot must prove Solana confirmation`);
    assertCondition(isHex(snapshotRootHex, 32), `${source}.snapshot.snapshotRootHex must be 32 bytes`);
    assertCondition(isHex(payloadHex) && payloadHex.length > 0, `${source}.snapshot.payloadHex must be non-empty hex`);

    const outputCount = requiredNumber(withdrawal, "outputCount", `${source}.withdrawal`);
    assertCondition(Number.isSafeInteger(outputCount) && outputCount > 0, `${source}.withdrawal.outputCount must be positive`);
    const outputs = withdrawal.outputs;
    if (outputs !== undefined) {
        assertCondition(Array.isArray(outputs) && outputs.length === outputCount, `${source}.withdrawal.outputs length mismatch`);
        for (const [index, output] of outputs.entries()) {
            assertCondition(isObject(output), `${source}.withdrawal.outputs[${index}] must be an object`);
            assertCondition(requiredNumber(output, "amountSats", `${source}.withdrawal.outputs[${index}]`) > 0, `${source} output amount must be positive`);
            assertCondition(isHex(requiredString(output, "recipientAddressHex", `${source}.withdrawal.outputs[${index}]`), 20), `${source} recipient must be 20 bytes`);
        }
    }

    const required = requiredNumber(manager, "required", `${source}.manager`);
    const total = requiredNumber(manager, "total", `${source}.manager`);
    assertCondition(required === MANAGER_QUORUM_M && total === MANAGER_QUORUM_N, `${source}.manager must be ${MANAGER_QUORUM_M}-of-${MANAGER_QUORUM_N}`);
    const signerIndices = manager.signerIndices;
    assertCondition(Array.isArray(signerIndices) && signerIndices.length >= required, `${source}.manager signer quorum is missing`);
    const uniqueSigners = new Set<number>();
    for (const signer of signerIndices) {
        assertCondition(Number.isInteger(signer) && Number(signer) >= 0 && Number(signer) < total, `${source}.manager signer index is invalid`);
        uniqueSigners.add(Number(signer));
    }
    assertCondition(uniqueSigners.size === signerIndices.length, `${source}.manager signer indices must be unique`);
    const vaaHashHex = requiredString(manager, "vaaHashHex", `${source}.manager`).toLowerCase();
    const signedVaaSha256Hex = requiredString(manager, "signedVaaSha256Hex", `${source}.manager`).toLowerCase();
    assertCondition(isHex(vaaHashHex, 32) && isHex(signedVaaSha256Hex, 32), `${source}.manager VAA identities must be 32-byte hex`);

    const signedTransactionHex = requiredString(dogecoin, "signedTransactionHex", `${source}.dogecoin`).toLowerCase();
    const txid = requiredString(dogecoin, "txid", `${source}.dogecoin`).toLowerCase();
    assertCondition(isHex(signedTransactionHex) && signedTransactionHex.length > 0, `${source}.dogecoin signed transaction is invalid`);
    assertCondition(isHex(txid, 32), `${source}.dogecoin.txid must be 32-byte hex`);
    assertCondition(dogecoin.broadcast === true, `${source}.dogecoin.broadcast must be true`);
    assertCondition(evidence.completed === true, `${source}.completed must record the broadcast stage`);
    const reservationId = requiredString(custody, "reservationId", `${source}.custody`);

    let confirmed = false;
    const store: JsonObject | null = options.operatorStore ?? null;
    if (options.requireConfirmed) {
        assertCondition(store, `${source} requires OperatorStore Confirmed evidence`);
        assertCondition(requiredString(store, "schema", "operatorStore") === "doge-operator-store-confirmed-snapshot-v1", `operatorStore schema mismatch`);
        assertCondition(requiredString(store, "snapshotSignature", "operatorStore") === snapshotSignature, `operatorStore snapshot signature mismatch`);
        assertCondition(requiredString(store, "snapshotStatus", "operatorStore") === "confirmed", `operatorStore snapshot is not confirmed`);
        assertCondition(requiredNumber(store, "requestStart", "operatorStore") === requestStart, `operatorStore request start mismatch`);
        assertCondition(requiredNumber(store, "requestEnd", "operatorStore") === requestEnd, `operatorStore request end mismatch`);
        assertCondition(requiredString(store, "processStatus", "operatorStore") === "confirmed", `operatorStore process is not confirmed`);
        assertCondition(requiredString(store, "dogecoinStatus", "operatorStore") === "confirmed", `operatorStore Dogecoin transaction is not confirmed`);
        assertCondition(requiredString(store, "reservationStatus", "operatorStore") === "spent", `operatorStore reservation is not spent`);
        assertCondition(requiredString(store, "reservationId", "operatorStore") === reservationId, `operatorStore reservation identity mismatch`);
        assertCondition(requiredString(store, "txid", "operatorStore").toLowerCase() === txid, `operatorStore txid mismatch`);
        const txidInternalHex = requiredString(store, "txidInternalHex", "operatorStore").toLowerCase();
        assertCondition(requiredString(store, "reservationSpendTxidInternalHex", "operatorStore").toLowerCase() === txidInternalHex, `operatorStore reservation spend txid mismatch`);
        assertCondition(requiredNumber(store, "wormholeSequence", "operatorStore") === sequence, `operatorStore Wormhole sequence mismatch`);
        assertCondition(requiredString(store, "snapshotRootHex", "operatorStore").toLowerCase() === snapshotRootHex, `operatorStore snapshot root mismatch`);
        assertCondition(requiredString(store, "payloadHashHex", "operatorStore").toLowerCase() === sha256Hex(Buffer.from(payloadHex, "hex")), `operatorStore payload hash mismatch`);
        assertCondition(requiredNumber(store, "blockHeight", "operatorStore") >= 0, `operatorStore block height is invalid`);
        assertCondition(requiredNumber(store, "confirmations", "operatorStore") >= 1, `operatorStore confirmation count is zero`);
        const requests = store.requests;
        assertCondition(Array.isArray(requests) && requests.length === requestEnd - requestStart, `operatorStore confirmed request range is incomplete`);
        assertCondition(requests.every((request, offset) => isObject(request) && request.index === requestStart + offset && request.status === "confirmed"), `operatorStore request identity/status is not Confirmed`);
        const inputs = store.inputs;
        assertCondition(Array.isArray(inputs) && inputs.length > 0, `operatorStore has no selected custody inputs`);
        assertCondition(inputs.every((input) => isObject(input) && input.status === "spent" && typeof input.spendTxidInternalHex === "string" && input.spendTxidInternalHex.toLowerCase() === txidInternalHex), `operatorStore custody inputs are not the matching Spent transaction`);
        confirmed = true;
    }

    return {
        schema,
        snapshotSignature,
        snapshotSlot,
        requestStart,
        requestEnd,
        snapshotRootHex,
        sequence,
        payloadSha256Hex: sha256Hex(Buffer.from(payloadHex, "hex")),
        outputCount,
        recipientAmountSats: Array.isArray(outputs) && isObject(outputs[0]) ? outputs[0].amountSats ?? null : null,
        vaaHashHex,
        signedVaaSha256Hex,
        managerRequired: required,
        managerTotal: total,
        signatureCount: signerIndices.length,
        signerIndices,
        signedRawBytes: Buffer.from(signedTransactionHex, "hex").length,
        signedRawSha256Hex: sha256Hex(Buffer.from(signedTransactionHex, "hex")),
        txid,
        broadcast: true,
        broadcastCompleted: true,
        operatorStoreConfirmed: confirmed,
        confirmationBlockHeight: store && typeof store.blockHeight === "number" ? store.blockHeight : null,
        confirmationCount: store && typeof store.confirmations === "number" ? store.confirmations : null,
        reservationStatus: store && typeof store.reservationStatus === "string" ? store.reservationStatus : null,
        verified: true,
    };
}

export function buildCompletionEvidence(block: JsonObject, withdrawal: JsonObject): JsonObject {
    const blockVerified = block.verified === true;
    const withdrawalVerified = withdrawal.verified === true;
    return {
        schema: "doge-single-block-zk-completion-v2",
        blockProof: blockVerified ? {
            kind: "block-update-groth16",
            height: block.height ?? null,
            contentSha256: block.contentSha256 ?? null,
            proofPath: block.proofPath ?? null,
            proofBytes: block.proofBytes ?? null,
            proofSha256Hex: block.proofSha256Hex ?? null,
            publicValuesBytes: block.publicValuesBytes ?? null,
            publicValuesSha256Hex: block.publicValuesSha256Hex ?? null,
            vkHash: block.vkHash ?? null,
            elfSha256Hex: block.elfSha256Hex ?? null,
            inputsSha256Hex: block.inputsSha256Hex ?? null,
            verified: true,
        } : { kind: "block-update-groth16", verified: false },
        withdrawal: withdrawalVerified ? {
            kind: "snapshot-outputs-only-utx0",
            snapshotSignature: withdrawal.snapshotSignature ?? null,
            snapshotRootHex: withdrawal.snapshotRootHex ?? null,
            payloadSha256Hex: withdrawal.payloadSha256Hex ?? null,
            wormholeSequence: withdrawal.sequence ?? null,
            vaaHashHex: withdrawal.vaaHashHex ?? null,
            signedVaaSha256Hex: withdrawal.signedVaaSha256Hex ?? null,
            managerQuorum: `${MANAGER_QUORUM_M}-of-${MANAGER_QUORUM_N}`,
            signatureCount: withdrawal.signatureCount ?? null,
            signedRawSha256Hex: withdrawal.signedRawSha256Hex ?? null,
            txid: withdrawal.txid ?? null,
            broadcast: withdrawal.broadcast ?? false,
            operatorStoreConfirmed: withdrawal.operatorStoreConfirmed ?? false,
            confirmationBlockHeight: withdrawal.confirmationBlockHeight ?? null,
            confirmationCount: withdrawal.confirmationCount ?? null,
            reservationStatus: withdrawal.reservationStatus ?? null,
            verified: true,
        } : { kind: "snapshot-outputs-only-utx0", verified: false },
        singleZk: blockVerified,
        withdrawalZk: false,
    };
}

export function evaluateCompletion(input: {
    blockManifest: JsonObject | null;
    withdrawalEvidence: JsonObject | null;
    operatorStoreEvidence: JsonObject | null;
    mintSats: number | null;
    burnSats: number | null;
    requireFullLive: boolean;
}): CompletionValidation {
    const reasons: string[] = [];
    let block: JsonObject = { verified: false };
    let withdrawal: JsonObject = { verified: false };
    if (input.blockManifest) {
        try { block = validateBlockProofEvidence(input.blockManifest, { requireDeposit: true, requireMinted: input.requireFullLive }); }
        catch (error) { reasons.push(`block proof validation failed: ${error instanceof Error ? error.message : String(error)}`); }
    } else reasons.push("missing block_update proof evidence");
    if (input.withdrawalEvidence) {
        try { withdrawal = validateWithdrawalEvidence(input.withdrawalEvidence, { requireConfirmed: input.requireFullLive, operatorStore: input.operatorStoreEvidence ?? undefined }); }
        catch (error) { reasons.push(`withdrawal evidence validation failed: ${error instanceof Error ? error.message : String(error)}`); }
    } else reasons.push("missing snapshot withdrawal evidence");
    if (input.requireFullLive) {
        if (input.mintSats !== EXPECTED_NET_MINT_SATS) reasons.push(`mint amount ${input.mintSats} != ${EXPECTED_NET_MINT_SATS}`);
        if (input.burnSats !== BURN_AMOUNT_SATS) reasons.push(`burn amount ${input.burnSats} != ${BURN_AMOUNT_SATS}`);
        if (block.verified !== true) reasons.push("block_update ZK proof is not verified");
        if (withdrawal.verified !== true) reasons.push("snapshot withdrawal evidence is not verified");
        if (withdrawal.operatorStoreConfirmed !== true) reasons.push("OperatorStore Confirmed graph is missing");
        if (typeof withdrawal.signatureCount !== "number" || withdrawal.signatureCount < MANAGER_QUORUM_M) reasons.push(`expected at least ${MANAGER_QUORUM_M} Manager signatures`);
    } else reasons.push("full-live gate is disabled; completed remains false");
    const evidence = buildCompletionEvidence(block, withdrawal);
    return { completedEligible: reasons.length === 0, block, withdrawal, evidence, reasons };
}

function bundleCompletionEvidence(validation: CompletionValidation, extra: JsonObject = {}): JsonObject {
    return { completedEligible: validation.completedEligible, reasons: validation.reasons, evidence: validation.evidence, block: validation.block, withdrawal: validation.withdrawal, ...extra };
}

function logPhase(number: number, name: string): void {
    console.log(`\n=== Phase ${number}: ${name} ===`);
}

async function runDryPlan(options: Options, evidence: Evidence): Promise<void> {
    const command = launcherCommand(options);
    logPhase(1, "Non-destructive infrastructure plan");
    console.log(command.map(shellQuote).join(" "));
    logPhase(2, "Deposit and block_update plan");
    console.log(`${CLI_BIN} deposit ... (funding WIF redacted); local flow mines ${DEPOSIT_PIPELINE_BLOCKS_TO_MINE} blocks while deposit waits for confirmation`);
    console.log(`Require one ${GROTH16_PROOF_SIZE}-byte block_update proof and a minted ${BLOCK_PROOF_LATEST_PATH}`);
    logPhase(3, "Burn and snapshot withdrawal plan");
    console.log(`Burn ${BURN_AMOUNT_SATS} pDOGE, run ${CLI_BIN} withdraw, require outputs-only UTX0, Wormhole sequence/VAA, and ${MANAGER_QUORUM_M}-of-${MANAGER_QUORUM_N}`);
    console.log("After broadcast, mine locally, run withdraw --resume, and require the entire OperatorStore graph to be Confirmed/Spent");
    evidence.phases.plan = {
        launcherCommand: command,
        chainSideEffects: false,
        cliBinary: CLI_BIN,
        cliSubcommands: ["deposit", "withdraw"],
        blockProofLatest: BLOCK_PROOF_LATEST_PATH,
        withdrawalEvidence: WITHDRAWAL_EVIDENCE_PATH,
        managerQuorum: `${MANAGER_QUORUM_M}-of-${MANAGER_QUORUM_N}`,
        singleZk: "block_update only",
        snapshotAuthorization: true,
        outputsOnlyUtx0: true,
        offChainConfirmation: true,
    };
    const validation = evaluateCompletion({ blockManifest: null, withdrawalEvidence: null, operatorStoreEvidence: null, mintSats: null, burnSats: null, requireFullLive: false });
    evidence.completion = bundleCompletionEvidence(validation, { dryPlan: true });
    evidence.completed = false;
    evidence.finishedAt = new Date().toISOString();
    console.log("\nDRY-PLAN complete: no files, services, chains, funds, or temporary directories were modified");
}


async function waitForLauncherReady(launcher: Bun.Subprocess, options: Options): Promise<BridgeOutput> {
    return await Promise.race([
        waitFor("bridge/users/Manager/Electrs readiness", 240_000, async () => {
            if (!fs.existsSync(BRIDGE_OUTPUT_PATH) || !fs.existsSync(USER_OUTPUT_PATH) || !fs.existsSync(FUNDING_ARTIFACT_PATH)) return false;
            try {
                const [health, tip, managerProbe] = await Promise.all([
                    solanaRpc("getHealth"),
                    electrsGet("/blocks/tip/height"),
                    fetch(`${MANAGER_SERVICE_URL}/v1/signed_vaa/1/${"00".repeat(32)}/0`),
                ]);
                if (health !== "ok" || !Number.isFinite(Number(tip)) || managerProbe.status !== 404) return false;
                return loadBridgeOutput();
            } catch { return false; }
        }),
        launcher.exited.then((exitCode) => { throw new Error(`Local launcher exited before readiness with code ${exitCode}`); }),
    ]);
}

async function waitForBroadcastEvidence(command: RunningCommand): Promise<{ raw: JsonObject; txid: string; snapshotSignature: string }> {
    return await waitForArtifactWhileRunning(command, "withdraw broadcast evidence", 240_000, async () => {
        if (!fs.existsSync(WITHDRAWAL_EVIDENCE_PATH)) return false;
        try {
            const raw = readJsonObject(WITHDRAWAL_EVIDENCE_PATH);
            const snapshot = optionalObject(raw, "snapshot");
            const dogecoin = optionalObject(raw, "dogecoin");
            if (!snapshot || !dogecoin || dogecoin.broadcast !== true) return false;
            const txid = requiredString(dogecoin, "txid", "withdrawalEvidence.dogecoin");
            const snapshotSignature = requiredString(snapshot, "signature", "withdrawalEvidence.snapshot");
            return { raw, txid, snapshotSignature };
        } catch { return false; }
    });
}

async function runLive(options: Options, evidence: Evidence): Promise<void> {
    evidence.phases.preflight = preflightLocalBinaries();
    writeEvidence(evidence);
    for (const stale of [DEPOSIT_EVIDENCE_PATH, WITHDRAWAL_EVIDENCE_PATH]) fs.rmSync(stale, { force: true });
    fs.rmSync(FUNDING_ARTIFACT_PATH, { force: true });
    fs.rmSync(BLOCK_PROOF_EVIDENCE_ROOT, { recursive: true, force: true });

    let launcher: Bun.Subprocess | null = null;
    let launcherLogs: { stdoutLog: string; stderrLog: string } | null = null;
    let activeCommand: RunningCommand | null = null;
    try {
        logPhase(1, "Full localhost infrastructure with dogecoind");
        const started = await startLauncher(options);
        launcher = started.process;
        launcherLogs = { stdoutLog: started.stdoutLog, stderrLog: started.stderrLog };
        const bridge = await waitForLauncherReady(launcher, options);
        const bridgeBefore = await readBridgeProgress(bridge.bridgeStatePda);
        evidence.phases.infrastructure = {
            ready: true,
            launcherPid: launcher.pid,
            profile: "local",
            dogecoind: true,
            electrsUrl: ELECTRS_URL,
            bridgeStatePda: bridge.bridgeStatePda,
            userPubkey: bridge.userPubkey,
            userTokenAccount: bridge.userTokenAccount,
            bridgeBefore,
            components: ["block-sender", "ibc-pipeline", "manager-service"],
        };
        writeEvidence(evidence);

        for (const suffix of ["", "-wal", "-shm"]) fs.rmSync(`${bridge.operatorStore}${suffix}`, { force: true });
        const funding = readLocalFunding(FUNDING_ARTIFACT_PATH);
        fs.rmSync(FUNDING_ARTIFACT_PATH, { force: true });

        logPhase(2, "Deposit to custody with confirmation timing owned by the local smoke flow");
        const balanceBeforeDeposit = await tokenBalance(bridge.userTokenAccount);
        const { partialDeposit, depositMining, depositResult } = await (async () => {
            let depositCommand: RunningCommand | null = null;
            try {
                depositCommand = startCommand(CLI_BIN, depositArgs(bridge, funding), { cwd: LOCAL_OPS_ROOT });
                activeCommand = depositCommand;
                const partialDeposit = await waitForArtifactWhileRunning(depositCommand, "deposit broadcast evidence", 180_000, async () => {
                    if (!fs.existsSync(DEPOSIT_EVIDENCE_PATH)) return false;
                    try {
                        const raw = readJsonObject(DEPOSIT_EVIDENCE_PATH);
                        const deposit = optionalObject(raw, "deposit");
                        if (!deposit) return false;
                        const txid = deposit.txid;
                        return typeof txid === "string" && txid.length > 0 ? { raw, txid } : false;
                    } catch { return false; }
                });
                const depositMining: JsonObject | null = await mineBlocks(DEPOSIT_PIPELINE_BLOCKS_TO_MINE, funding.address);
                const depositResult = await depositCommand.result;
                return { partialDeposit, depositMining, depositResult };
            } finally {
                await stopCommand(depositCommand);
                if (activeCommand === depositCommand) activeCommand = null;
                fs.rmSync(FUNDING_WIF_PATH, { force: true });
            }
        })();
        const completedDeposit = readJsonObject(DEPOSIT_EVIDENCE_PATH);
        assertCondition(completedDeposit.completed === true, "deposit evidence did not reach completed=true");
        const depositObject = optionalObject(completedDeposit, "deposit");
        assertCondition(depositObject, "deposit evidence is missing deposit section");
        assertCondition(requiredString(depositObject, "txid", "depositEvidence.deposit") === partialDeposit.txid, "deposit txid changed between evidence stages");
        evidence.phases.deposit = {
            command: commandEvidence(depositResult),
            txid: partialDeposit.txid,
            amountSats: DEPOSIT_AMOUNT_SATS,
            fundingOutpoint: `${funding.txid}:${funding.vout}`,
            fundingValueSats: funding.value,
            fundingSecretRecorded: false,
            mining: depositMining,
            confirmationHeight: depositObject.confirmation_height ?? null,
            confirmations: depositObject.confirmations ?? null,
        };
        writeEvidence(evidence);

        logPhase(3, "Wait for block_update proof and pDOGE mint");
        const blockManifest = await waitFor("minted block_update evidence", 900_000, async () => {
            if (!fs.existsSync(BLOCK_PROOF_LATEST_PATH)) return false;
            try {
                const manifest = readJsonObject(BLOCK_PROOF_LATEST_PATH);
                validateBlockProofEvidence(manifest, { requireDeposit: true, requireMinted: true });
                return manifest;
            } catch { return false; }
        }, 2_000);
        const mintedBalance = await waitFor("expected pDOGE mint", 900_000, async () => {
            const balance = await tokenBalance(bridge.userTokenAccount);
            const delta = balance.amount - balanceBeforeDeposit.amount;
            return delta === BigInt(EXPECTED_NET_MINT_SATS) ? balance : false;
        }, 1_000);
        const bridgeAfterMint = await readBridgeProgress(bridge.bridgeStatePda);
        evidence.phases.blockUpdateAndMint = {
            block: validateBlockProofEvidence(blockManifest, { requireDeposit: true, requireMinted: true }),
            balanceBeforeSats: balanceBeforeDeposit.amount.toString(),
            balanceAfterSats: mintedBalance.amount.toString(),
            mintedDeltaSats: (mintedBalance.amount - balanceBeforeDeposit.amount).toString(),
            bridgeAfterMint,
            singleZk: true,
        };
        writeEvidence(evidence);

        logPhase(4, "Burn pDOGE and append request_withdrawal");
        const recipientPayload = createHash("sha256").update(`doge-local-smoke-withdrawal-${Date.now()}`).digest().subarray(0, 20);
        const recipientAddress = p2shAddress(recipientPayload);
        const user = loadSolanaKeypair(USER_OUTPUT_PATH, "private_key");
        const payer = loadSolanaKeypair(bridge.payerKeypair);
        assertCondition(user.publicKey.toBase58() === bridge.userPubkey, "user keypair does not match bridge output");
        assertCondition(payer.publicKey.toBase58() === bridge.payerPubkey, "payer keypair does not match bridge output");
        const burnSignature = await requestWithdrawal(payer, user, bridge.userTokenAccount, bridge.dogeMint, recipientAddress);
        const afterBurn = await waitFor("pDOGE burn", 60_000, async () => {
            const balance = await tokenBalance(bridge.userTokenAccount);
            return balance.amount === mintedBalance.amount - BigInt(BURN_AMOUNT_SATS) ? balance : false;
        }, 500);
        evidence.phases.request = {
            signature: burnSignature,
            grossAmountSats: BURN_AMOUNT_SATS,
            netAmountSats: EXPECTED_NET_WITHDRAWAL_SATS,
            recipientAddress,
            balanceBeforeSats: mintedBalance.amount.toString(),
            balanceAfterSats: afterBurn.amount.toString(),
        };
        writeEvidence(evidence);

        logPhase(5, "Snapshot withdrawals, relay outputs-only UTX0, collect Manager 5/7, and broadcast");
        const firstWithdrawal = startCommand(CLI_BIN, withdrawalArgs(bridge), { cwd: LOCAL_OPS_ROOT });
        activeCommand = firstWithdrawal;
        const broadcast = await waitForBroadcastEvidence(firstWithdrawal);
        const withdrawalMining: JsonObject | null = await mineBlocks(1, funding.address);
        await waitFor("Electrs withdrawal confirmation", 120_000, async () => {
            const transaction = await electrsGet(`/tx/${broadcast.txid}`);
            return isObject(transaction) && isObject(transaction.status) && transaction.status.confirmed === true ? true : false;
        }, 500);
        const firstWithdrawalResult = await firstWithdrawal.result;
        activeCommand = null;

        logPhase(6, "Resume CLI confirmation and atomically persist the Confirmed OperatorStore graph");
        const confirmationCommand = startCommand(CLI_BIN, withdrawalArgs(bridge, true), { cwd: LOCAL_OPS_ROOT });
        activeCommand = confirmationCommand;
        const confirmationResult = await confirmationCommand.result;
        activeCommand = null;
        const operatorStore = readOperatorStoreEvidence(bridge.operatorStore, broadcast.snapshotSignature);
        const withdrawalValidated = validateWithdrawalEvidence(broadcast.raw, { requireConfirmed: true, operatorStore });
        assertCondition(typeof withdrawalValidated.signatureCount === "number" && withdrawalValidated.signatureCount >= MANAGER_QUORUM_M, `expected at least ${MANAGER_QUORUM_M} Manager signatures`);
        assertCondition(withdrawalValidated.operatorStoreConfirmed === true, "OperatorStore graph did not reach Confirmed/Spent");
        evidence.phases.withdrawal = {
            broadcastCommand: commandEvidence(firstWithdrawalResult),
            confirmationCommand: commandEvidence(confirmationResult),
            mining: withdrawalMining,
            evidenceFile: WITHDRAWAL_EVIDENCE_PATH,
            withdrawal: withdrawalValidated,
            operatorStore,
            snapshotAuthorization: true,
            outputsOnlyUtx0: true,
            managerQuorum: `${MANAGER_QUORUM_M}-of-${MANAGER_QUORUM_N}`,
            offChainConfirmation: true,
        };
        writeEvidence(evidence);

        logPhase(7, "Completion gates");
        const validation = evaluateCompletion({
            blockManifest,
            withdrawalEvidence: broadcast.raw,
            operatorStoreEvidence: operatorStore,
            mintSats: Number(mintedBalance.amount - balanceBeforeDeposit.amount),
            burnSats: BURN_AMOUNT_SATS,
            requireFullLive: true,
        });
        assertCondition(validation.completedEligible, validation.reasons.join("; "));
        evidence.completion = bundleCompletionEvidence(validation, {
            flow: [
                "deposit",
                "Dogecoin confirmation",
                "block_update Groth16 proof",
                "pDOGE mint",
                "request_withdrawal burn",
                "snapshot_withdrawals",
                "outputs-only UTX0 Wormhole payload",
                "Manager 5/7",
                "Dogecoin broadcast",
                "Electrs confirmation",
                "OperatorStore Confirmed/Spent",
            ],
        });
        evidence.completed = true;
        evidence.finishedAt = new Date().toISOString();
        writeEvidence(evidence);
        console.log("\nPASS: complete localhost deposit -> block_update -> mint -> burn -> snapshot -> Manager 5/7 -> broadcast -> Confirmed OperatorStore flow");
        console.log(`Evidence: ${EVIDENCE_PATH}`);
    } catch (error) {
        evidence.completed = false;
        evidence.failure = { message: error instanceof Error ? error.message : String(error), stack: error instanceof Error ? error.stack : undefined };
        evidence.finishedAt = new Date().toISOString();
        writeEvidence(evidence);
        throw error;
    } finally {
        await stopCommand(activeCommand);
        fs.rmSync(FUNDING_WIF_PATH, { force: true });
        fs.rmSync(FUNDING_ARTIFACT_PATH, { force: true });
        if (launcher) {
            evidence.phases.cleanup = await stopLauncher(launcher);
            if (launcherLogs) {
                evidence.phases.launcherOutput = {
                    stdoutLog: launcherLogs.stdoutLog,
                    stderrLog: launcherLogs.stderrLog,
                    stdout: compactOutput(fs.existsSync(launcherLogs.stdoutLog) ? fs.readFileSync(launcherLogs.stdoutLog, "utf8") : ""),
                    stderr: compactOutput(fs.existsSync(launcherLogs.stderrLog) ? fs.readFileSync(launcherLogs.stderrLog, "utf8") : ""),
                };
            }
            if (evidence.failure) evidence.completed = false;
            writeEvidence(evidence);
        }
    }
}

async function main(): Promise<void> {
    const options = parseOptions();
    if (!options) return;
    const evidence: Evidence = {
        schema: "doge-bun-local-smoke-v1-durable-snapshot",
        startedAt: new Date().toISOString(),
        completed: false,
        profile: "local",
        mode: options.dryRun ? "dry-plan" : "full-live-localhost",
        dogeNetwork: "regtest",
        withdrawalMode: {
            snapshotAuthorization: true,
            outputsOnlyUtx0: true,
            managerSigningEnabled: true,
            broadcastEnabled: !options.dryRun,
            managerQuorum: `${MANAGER_QUORUM_M}-of-${MANAGER_QUORUM_N}`,
            offChainConfirmation: true,
        },
        paths: {
            cliRepo: CLI_REPO,
            sourceProjectsDir: SOURCE_PROJECTS_DIR,
            isolatedProjectsDir: PROJECTS_DIR,
            portOffset: LOCAL_PORT_OFFSET,
            stateHome: path.join(SMOKE_TMP_ROOT, "state"),
            ibcRepo: IBC_REPO,
            bridgeRepo: BRIDGE_REPO,
            senderRepo: SENDER_REPO,
            sp1Repo: SP1_REPO,
            localLauncher: LOCAL_LAUNCHER,
            cliBinary: CLI_BIN,
            bridgeOutput: BRIDGE_OUTPUT_PATH,
            userOutput: USER_OUTPUT_PATH,
            depositEvidence: DEPOSIT_EVIDENCE_PATH,
            withdrawalEvidence: WITHDRAWAL_EVIDENCE_PATH,
            blockProofLatest: BLOCK_PROOF_LATEST_PATH,
            finalEvidence: EVIDENCE_PATH,
        },
        phases: {},
    };
    if (options.dryRun) {
        await runDryPlan(options, evidence);
        return;
    }
    prepareIsolatedProjects();
    writeEvidence(evidence);
    await runLive(options, evidence);
}

main().catch((error) => {
    console.error(`\nLOCAL SMOKE FAILED: ${error instanceof Error ? error.message : String(error)}`);
    console.error(`Evidence: ${EVIDENCE_PATH}`);
    process.exitCode = 1;
});
