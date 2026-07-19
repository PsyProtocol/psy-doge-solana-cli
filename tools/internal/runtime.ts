#!/usr/bin/env bun

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { connect } from "node:net";
import { parseArgs } from "node:util";
import bs58 from "bs58";
import { PublicKey } from "@solana/web3.js";

type Profile = "local";
type Component = "dogecoin" | "electrs" | "solana" | "initialize" | "users" | "noop-monitor" | "block-sender" | "ibc-pipeline" | "manager-service" | "deposit" | "withdraw";
type DeploymentCluster = "devnet";
type DeploymentPolicy = "new" | "upgrade" | "auto";
type Commitment = "processed" | "confirmed" | "finalized";

type DeploymentOptions = {
    cluster: DeploymentCluster;
    rpcUrl: string;
    payerKeypair: string;
    upgradeAuthorityKeypair: string;
    programKeyDir?: string;
    programKeypairs: Partial<Record<string, string>>;
    wormholeCoreId: string;
    wormholeShimId: string;
    policy: DeploymentPolicy;
    manifestPath: string;
    commitment: Commitment;
    yes: boolean;
};

type ProcessRecord = {
    role: string;
    pid: number;
    startTicks: string;
    command: string[];
    cwd: string;
    stdoutLog: string;
    stderrLog: string;
};

type ContainerRecord = { role: string; id: string; name: string };
type ActiveState = {
    version: 1;
    runId: string;
    createdAt: string;
    runDir: string;
    processes: ProcessRecord[];
    containers: ContainerRecord[];
};

type Program = { name: string; keypair?: string; elf: string; id?: string };

type Options = {
    profile: Profile;
    dryRun: boolean;
    noBuild: boolean;
    rebuildPrograms: boolean;
    deploy?: DeploymentOptions;
    teardown: boolean;
    purge: boolean;
    components: Set<Component>;
    projectsDir: string;
    bridgeRepo: string;
    dogecoinRepo: string;
    electrsRepo: string;
    sp1Repo: string;
    dogeRpcUser: string;
    dogeRpcPassword: string;
    dogecoind: boolean;
    deposit: boolean;
    withdraw: boolean;
    fundingWifFile?: string;
    fundingTxid?: string;
    fundingVout?: number;
    fundingAmount?: number;
    localSmokeFundingArtifact?: string;
    recipientTokenAccount?: string;
    requestIndex?: number;
};

const SCRIPT_DIR = import.meta.dir;
const CLI_REPO = path.resolve(SCRIPT_DIR, "../..");
const DEFAULT_PROJECTS_DIR = path.resolve(CLI_REPO, "..");
const STATE_ROOT = path.resolve(
    process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"),
    "psy-doge-local",
);
const ACTIVE_STATE_PATH = path.join(STATE_ROOT, "active.json");
const DATA_ROOT = path.join(STATE_ROOT, "data");
const DOGE_DATA_DIR = path.join(DATA_ROOT, "dogecoin-regtest");
const ELECTRS_DATA_DIR = path.join(DATA_ROOT, "electrs-regtest");
const SOLANA_LEDGER_DIR = path.join(DATA_ROOT, "solana-ledger");
const LOCAL_PORT_OFFSET = Number.parseInt(process.env.PSY_DOGE_LOCAL_PORT_OFFSET || "0", 10);
if (!Number.isInteger(LOCAL_PORT_OFFSET) || LOCAL_PORT_OFFSET < 0 || LOCAL_PORT_OFFSET > 5_000) {
    throw new Error("PSY_DOGE_LOCAL_PORT_OFFSET must be an integer from 0 through 5000");
}
const localPort = (base: number): number => base + LOCAL_PORT_OFFSET;
const DOGE_RPC_URL = `http://127.0.0.1:${localPort(22555)}`;
const SOLANA_RPC_URL = `http://127.0.0.1:${localPort(8899)}`;
const ELECTRS_HTTP_URL = `http://127.0.0.1:${localPort(3002)}`;
const BLOCK_SENDER_PORT = localPort(3000);
const MANAGER_SERVICE_PORT = localPort(7071);
const BLOCK_SENDER_API_TOKEN = "local-smoke-token";
const DELEGATED_MANAGER_SET_ID = "wdmsTJP6YnsfeQjPuuEzGCrHmZvTmNy8VkxMCK8JkBX";
const LOCAL_NOOP_SHIM_ID = "FwDChsHWLwbhTiYQ4Sum5mjVWswECi9cmrA11GUFUuxi";
const DOGECOIN_WORMHOLE_CHAIN_ID = 65;
const LOCAL_MANAGER_SET_INDEX = 0;
const LOCAL_MANAGER_SET_PREFIX = Buffer.from([0x01, 0x05, 0x07]);
const LOCAL_MANAGER_SET_PUBKEYS = [
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
    "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
    "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
    "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
] as const;
const LOCAL_MANAGER_SET_BYTES = Buffer.concat([
    LOCAL_MANAGER_SET_PREFIX,
    ...LOCAL_MANAGER_SET_PUBKEYS.map((key) => Buffer.from(key, "hex")),
]);
const BRIDGE_STATE_PDA = "9vzbk8X27e6VRcCPWCyxZsa2DV6GLQ3y9e1mXzfAgUdX";
const PUBLIC_WORMHOLE_DEVNET_CORE_ID = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";
const PUBLIC_WORMHOLE_DEVNET_SHIM_ID = "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";
const SOLANA_GENESIS_HASHES = {
    devnet: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
} as const;
const UPGRADEABLE_LOADER_ID = "BPFLoaderUpgradeab1e11111111111111111111111";
const PUBLIC_PROGRAM_NAMES = ["doge-bridge", "pending-mint-buffer", "txo-buffer", "generic-buffer", "manual-claim"] as const;
const PUBLIC_PROGRAM_IDS: Record<(typeof PUBLIC_PROGRAM_NAMES)[number], string> = {
    "doge-bridge": "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ",
    "pending-mint-buffer": "PMUSqycT1j5JTLmHk8frGSCido2h9VG1pyh2MPEa33o",
    "txo-buffer": "TXWhjswto9q6hfaGPuAhDS79wAHKfbMJLVR178xYAaQ",
    "generic-buffer": "GBYLmevzPSBPWfWrJ1h9gNzHqUjDXETzHKL1AasLyKwC",
    "manual-claim": "MCdYbqiK3uj36tohbMjsh3Ssg8iRSJmSHToNxW8TWWE",
};

const LOCAL_SMOKE_FUNDING_SCHEMA = "psy-doge-local-smoke-funding-v1";
const LOCAL_SMOKE_FUNDING_BLOCKS = 110;
const LOCAL_SMOKE_MIN_CONFIRMATIONS = 100;
const LOCAL_SMOKE_MIN_VALUE_SATS = 101_000_000;
const REGTEST_P2PKH_VERSION = 0x6f;
const PORTS = {
    dogeRpc: localPort(22555),
    dogeP2p: localPort(18444),
    electrsHttp: localPort(3002),
    electrum: localPort(60401),
    electrsMetrics: localPort(24224),
    solanaRpc: localPort(8899),
    solanaWs: localPort(8900),
    solanaFaucet: localPort(9900),
    checkpointRedis: localPort(6379),
} as const;

function localUsage(): string {
    return `Doge localhost bridge launcher (Bun)

Usage:
  bun tools/local/launcher.ts --network localhost [local options]
  bun tools/local/launcher.ts --network localhost --deposit --funding-wif-file <mode-600-file> --funding-txid <hash> --funding-vout <n> --funding-amount <sats> --recipient-token-account <pubkey>
  bun tools/local/launcher.ts --network localhost --withdraw --request-index <n>

Network:
  --network localhost         Required. Devnet is rejected; use tools/deploy/devnet.ts.

Local components and lifecycle:
  --dogecoind                 Force local Dogecoin regtest plus local Electrs
  --dogecoin / --no-dogecoin Enable/disable local Dogecoin regtest
  --electrs                   Start local electrs-doge and wait for indexed tip
  --solana / --no-solana      Enable/disable local solana-test-validator
  --initialize                Initialize the local bridge
  --create-users              Create user1/user2/user3 locally
  --noop-monitor              Run the noop-shim monitor
  --block-sender              Start the TypeScript Solana block sender
  --ibc-pipeline              Start the Rust Dogecoin block proof/submission pipeline
  --manager-service           Start the local Manager/VAA HTTP service
  --prepare-local-smoke-funding <path>
                              Mine and select a mature local funding UTXO, then atomically write a mode-600 artifact
  --only <csv>                Replace the default component set
  --teardown                  Stop only launcher-recorded PIDs/container IDs
  --purge                     Teardown and remove launcher-owned state
  --preflight                 Read-only checks and exact plan; start no services
  --no-build                  Require existing binaries and program artifacts
  --rebuild-programs          Rebuild local Psy program artifacts
  --projects-dir <path>       Sibling repository root
  --bridge-repo <path>        psy-doge-solana-bridge override
  --dogecoin-repo <path>      Dogecoin Core source override
  --electrs-repo <path>       electrs-doge source override
  --sp1-repo <path>           psy-bridge-sp1 override
  --doge-rpc-user <user>      Local regtest RPC user
  --doge-rpc-password <pass>  Local regtest RPC password

One-shot operator modes:
  --deposit                   Run doge-solana-cli deposit in the foreground
  --funding-wif-file <path>   Mode-600 file containing only the funding Dogecoin WIF
  --funding-txid <hash>       Explicit funding UTXO transaction ID
  --funding-vout <n>          Explicit funding UTXO output index
  --funding-amount <sats>     Exact funding UTXO value in satoshis
  --recipient-token-account <pubkey>
  --withdraw                  Run doge-solana-cli withdraw in the foreground
  --request-index <n>         Authoritative Solana withdrawal request index
  -h, --help                  Show help`;
}

function deployUsage(): string {
    return `Psy Doge bridge deployment to Solana devnet (Bun)

Usage:
  bun tools/deploy/devnet.ts --network devnet --payer <keypair> --program-key-dir <dir> --preflight
  bun tools/deploy/devnet.ts --network devnet --payer <keypair> --program-key-dir <dir> --deployment-policy auto --yes

Network:
  --network devnet            Required. Localhost is rejected; use tools/local/launcher.ts.
  --rpc-url <url>             Solana RPC (default: https://api.devnet.solana.com)

Psy program deployment:
  --payer <path>              Fee payer keypair file
  --upgrade-authority <path>  Upgrade-authority keypair (default: payer)
  --program-key-dir <path>    Directory containing all five Psy program keypairs
  --doge-bridge-keypair <p>   Individual program keypair override
  --pending-mint-keypair <p>  Individual program keypair override
  --txo-buffer-keypair <p>    Individual program keypair override
  --generic-buffer-keypair <p>
  --manual-claim-keypair <p>
  --deployment-policy <p>     new|upgrade|auto (default: auto)
  --no-build                  Require existing verified public ELFs
  --rebuild-programs          Rebuild all public Psy ELFs
  --manifest <path>           Atomic deployment manifest output
  --commitment <level>        processed|confirmed|finalized (default: confirmed)
  --yes                       Required for every mutation
  --preflight                 Read-only checks and exact plan; no mutation
  --projects-dir <path>       Sibling repository root
  --bridge-repo <path>        psy-doge-solana-bridge override
  -h, --help                  Show help

The official Wormhole Testnet Core ${PUBLIC_WORMHOLE_DEVNET_CORE_ID} and shim
${PUBLIC_WORMHOLE_DEVNET_SHIM_ID} are verified, never deployed or upgraded. No local
Dogecoin, Electrs, validator, Manager, Sender, IBC, Redis, or SP1 service is started.`;
}

function fail(message: string): never {
    throw new Error(message);
}

function asString(value: unknown, fallback: string): string {
    return typeof value === "string" && value.length > 0 ? value : fallback;
}

function parseIntegerOption(value: unknown, flag: string, minimum: number): number | undefined {
    if (value === undefined) return undefined;
    const text = String(value);
    if (!/^\d+$/.test(text)) fail(`${flag} must be an integer greater than or equal to ${minimum}.`);
    const parsed = Number(text);
    if (!Number.isSafeInteger(parsed) || parsed < minimum) fail(`${flag} must be an integer greater than or equal to ${minimum}.`);
    return parsed;
}

function requireNetwork(value: unknown, expected: "localhost" | "devnet"): void {
    const network = asString(value, "");
    if (!network) fail(`--network ${expected} is required.`);
    if (network !== expected) fail(`This entrypoint only supports --network ${expected}; got '${network}'.`);
}

function requireRemoteHttpUrl(value: string, flag: string): string {
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        fail(`${flag} must be a valid http(s) URL.`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") fail(`${flag} must use http or https.`);
    const host = url.hostname.toLowerCase();
    const localName = host === "localhost" || host.endsWith(".localhost");
    const localIpv4 = /^(127\.|0\.|10\.|192\.168\.|169\.254\.)/.test(host)
        || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    const localIpv6 = host === "::" || host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe8") || host.startsWith("fe9") || host.startsWith("fea") || host.startsWith("feb");
    if (localName || localIpv4 || localIpv6) fail(`${flag} must be externally operated for --network devnet; local host '${url.hostname}' is forbidden.`);
    return url.toString();
}

function parseDeploymentPolicy(value: unknown): DeploymentPolicy {
    const policy = asString(value, "auto");
    if (!["new", "upgrade", "auto"].includes(policy)) fail("--deployment-policy must be new, upgrade, or auto.");
    return policy as DeploymentPolicy;
}

function parseCommitment(value: unknown): Commitment {
    const commitment = asString(value, "confirmed");
    if (!["processed", "confirmed", "finalized"].includes(commitment)) fail("--commitment must be processed, confirmed, or finalized.");
    return commitment as Commitment;
}


function resolveLocalOptions(args: string[]): Options | null {
    const { values } = parseArgs({
        args,
        strict: true,
        allowPositionals: false,
        options: {
            help: { type: "boolean", short: "h" },
            network: { type: "string" },
            preflight: { type: "boolean" },
            "no-build": { type: "boolean" },
            "rebuild-programs": { type: "boolean" },
            teardown: { type: "boolean" },
            purge: { type: "boolean" },
            dogecoin: { type: "boolean" },
            "no-dogecoin": { type: "boolean" },
            electrs: { type: "boolean" },
            solana: { type: "boolean" },
            "no-solana": { type: "boolean" },
            initialize: { type: "boolean" },
            "create-users": { type: "boolean" },
            "prepare-local-smoke-funding": { type: "string" },
            "noop-monitor": { type: "boolean" },
            "block-sender": { type: "boolean" },
            "ibc-pipeline": { type: "boolean" },
            "manager-service": { type: "boolean" },
            dogecoind: { type: "boolean" },
            deposit: { type: "boolean" },
            withdraw: { type: "boolean" },
            "funding-wif-file": { type: "string" },
            "funding-txid": { type: "string" },
            "funding-vout": { type: "string" },
            "funding-amount": { type: "string" },
            "recipient-token-account": { type: "string" },
            "request-index": { type: "string" },
            only: { type: "string" },
            "projects-dir": { type: "string" },
            "bridge-repo": { type: "string" },
            "dogecoin-repo": { type: "string" },
            "electrs-repo": { type: "string" },
            "sp1-repo": { type: "string" },
            "doge-rpc-user": { type: "string" },
            "doge-rpc-password": { type: "string" },
        },
    });
    if (values.help) {
        console.log(localUsage());
        return null;
    }
    requireNetwork(values.network, "localhost");
    if (values.dogecoin && values["no-dogecoin"]) fail("Use only one of --dogecoin and --no-dogecoin.");
    if (values.dogecoind && values["no-dogecoin"]) fail("--dogecoind cannot be combined with --no-dogecoin.");
    if (values.solana && values["no-solana"]) fail("Use only one of --solana and --no-solana.");
    if (values.deposit && values.withdraw) fail("Use only one of --deposit and --withdraw.");

    const projectsDir = path.resolve(asString(values["projects-dir"], DEFAULT_PROJECTS_DIR));
    const bridgeRepo = path.resolve(asString(values["bridge-repo"], path.join(projectsDir, "psy-doge-solana-bridge")));
    const fundingRaw = values["prepare-local-smoke-funding"];
    if (fundingRaw !== undefined && String(fundingRaw).trim().length === 0) fail("--prepare-local-smoke-funding requires a non-empty artifact path.");
    const localSmokeFundingArtifact = fundingRaw === undefined ? undefined : path.resolve(String(fundingRaw));

    let components = new Set<Component>(["dogecoin", "electrs", "solana", "initialize", "users"]);
    if (values.only) {
        components = new Set<Component>();
        const allowed: Record<Component, true> = {
            dogecoin: true, electrs: true, solana: true, initialize: true, users: true,
            "noop-monitor": true, "block-sender": true, "ibc-pipeline": true,
            "manager-service": true, deposit: true, withdraw: true,
        };
        for (const raw of values.only.split(",")) {
            const component = raw.trim() as Component;
            if (!allowed[component]) fail(`Unknown --only component '${raw.trim()}'.`);
            components.add(component);
        }
    }
    if (values.dogecoin) components.add("dogecoin");
    if (values["no-dogecoin"]) components.delete("dogecoin");
    if (values.electrs) components.add("electrs");
    if (values.solana) components.add("solana");
    if (values["no-solana"]) components.delete("solana");
    if (values.initialize) components.add("initialize");
    if (values["create-users"]) components.add("users");
    if (values["noop-monitor"]) components.add("noop-monitor");
    if (values["block-sender"]) components.add("block-sender");
    if (values["ibc-pipeline"]) components.add("ibc-pipeline");
    if (values["manager-service"]) components.add("manager-service");
    if (values.deposit) components.add("deposit");
    if (values.withdraw) components.add("withdraw");
    if (localSmokeFundingArtifact) {
        if (values["no-dogecoin"]) fail("--prepare-local-smoke-funding cannot be combined with --no-dogecoin.");
        components.add("dogecoin");
        components.add("electrs");
    }
    if (values.dogecoind) {
        components.add("dogecoin");
        components.add("electrs");
    }
    if (components.has("electrs")) components.add("dogecoin");
    if (components.has("users")) components.add("initialize");
    if (components.has("initialize")) components.add("solana");
    if (components.has("noop-monitor")) components.add("solana");
    if (components.has("ibc-pipeline")) components.add("block-sender");
    if (components.has("block-sender")) components.add("initialize");
    if (localSmokeFundingArtifact && !components.has("initialize")) fail("--prepare-local-smoke-funding requires --initialize (or a component set that initializes the bridge).");

    const deposit = Boolean(values.deposit || components.has("deposit"));
    const withdraw = Boolean(values.withdraw || components.has("withdraw"));
    if (deposit && withdraw) fail("Use only one of --deposit and --withdraw.");
    if ((deposit || withdraw) && (values.teardown || values.purge || localSmokeFundingArtifact)) fail("Operator modes cannot be combined with --teardown, --purge, or --prepare-local-smoke-funding.");
    const fundingVout = parseIntegerOption(values["funding-vout"], "--funding-vout", 0);
    const fundingAmount = parseIntegerOption(values["funding-amount"], "--funding-amount", 1);
    const requestIndex = parseIntegerOption(values["request-index"], "--request-index", 0);
    if (deposit) {
        const missing = [
            ["--funding-wif-file", values["funding-wif-file"]],
            ["--funding-txid", values["funding-txid"]],
            ["--funding-vout", fundingVout],
            ["--funding-amount", fundingAmount],
            ["--recipient-token-account", values["recipient-token-account"]],
        ].filter(([, value]) => value === undefined || value === "").map(([flag]) => flag);
        if (missing.length > 0) fail(`--deposit requires ${missing.join(", ")}.`);
    }
    if (withdraw && requestIndex === undefined) fail("--withdraw requires --request-index <n>.");

    let dogecoind = !values["no-dogecoin"];
    if (values.dogecoin || values.electrs || values.dogecoind || values.only?.split(",").some((component) => ["dogecoin", "electrs"].includes(component.trim()))) dogecoind = true;
    return {
        profile: "local",
        dryRun: Boolean(values.preflight),
        noBuild: Boolean(values["no-build"]),
        rebuildPrograms: Boolean(values["rebuild-programs"]),
        teardown: Boolean(values.teardown || values.purge),
        purge: Boolean(values.purge),
        components,
        projectsDir,
        bridgeRepo,
        dogecoinRepo: path.resolve(asString(values["dogecoin-repo"], path.join(projectsDir, "dogecoin"))),
        electrsRepo: path.resolve(asString(values["electrs-repo"], path.join(projectsDir, "electrs-doge"))),
        sp1Repo: path.resolve(asString(values["sp1-repo"], path.join(projectsDir, "psy-bridge-sp1"))),
        dogeRpcUser: asString(values["doge-rpc-user"], "doge"),
        dogeRpcPassword: asString(values["doge-rpc-password"], "doge"),
        dogecoind,
        deposit,
        withdraw,
        fundingWifFile: values["funding-wif-file"] ? path.resolve(String(values["funding-wif-file"])) : undefined,
        fundingTxid: values["funding-txid"] ? String(values["funding-txid"]) : undefined,
        fundingVout,
        fundingAmount,
        localSmokeFundingArtifact,
        recipientTokenAccount: values["recipient-token-account"] ? String(values["recipient-token-account"]) : undefined,
        requestIndex,
    };
}

function resolveDevnetOptions(args: string[]): Options | null {
    const { values } = parseArgs({
        args,
        strict: true,
        allowPositionals: false,
        options: {
            help: { type: "boolean", short: "h" },
            network: { type: "string" },
            preflight: { type: "boolean" },
            "rpc-url": { type: "string" },
            payer: { type: "string" },
            "upgrade-authority": { type: "string" },
            "program-key-dir": { type: "string" },
            "doge-bridge-keypair": { type: "string" },
            "pending-mint-keypair": { type: "string" },
            "txo-buffer-keypair": { type: "string" },
            "generic-buffer-keypair": { type: "string" },
            "manual-claim-keypair": { type: "string" },
            "deployment-policy": { type: "string" },
            "no-build": { type: "boolean" },
            "rebuild-programs": { type: "boolean" },
            manifest: { type: "string" },
            commitment: { type: "string" },
            yes: { type: "boolean" },
            "projects-dir": { type: "string" },
            "bridge-repo": { type: "string" },
        },
    });
    if (values.help) {
        console.log(deployUsage());
        return null;
    }
    requireNetwork(values.network, "devnet");
    if (!values.payer) fail("Devnet deployment requires --payer <keypair path>.");
    const projectsDir = path.resolve(asString(values["projects-dir"], DEFAULT_PROJECTS_DIR));
    const bridgeRepo = path.resolve(asString(values["bridge-repo"], path.join(projectsDir, "psy-doge-solana-bridge")));
    const payerKeypair = path.resolve(String(values.payer));
    const programKeyDir = values["program-key-dir"] ? path.resolve(String(values["program-key-dir"])) : undefined;
    const deploy: DeploymentOptions = {
        cluster: "devnet",
        rpcUrl: requireRemoteHttpUrl(asString(values["rpc-url"], "https://api.devnet.solana.com"), "--rpc-url"),
        payerKeypair,
        upgradeAuthorityKeypair: path.resolve(asString(values["upgrade-authority"], payerKeypair)),
        programKeyDir,
        programKeypairs: {
            "doge-bridge": values["doge-bridge-keypair"] ? path.resolve(String(values["doge-bridge-keypair"])) : undefined,
            "pending-mint-buffer": values["pending-mint-keypair"] ? path.resolve(String(values["pending-mint-keypair"])) : undefined,
            "txo-buffer": values["txo-buffer-keypair"] ? path.resolve(String(values["txo-buffer-keypair"])) : undefined,
            "generic-buffer": values["generic-buffer-keypair"] ? path.resolve(String(values["generic-buffer-keypair"])) : undefined,
            "manual-claim": values["manual-claim-keypair"] ? path.resolve(String(values["manual-claim-keypair"])) : undefined,
        },
        wormholeCoreId: PUBLIC_WORMHOLE_DEVNET_CORE_ID,
        wormholeShimId: PUBLIC_WORMHOLE_DEVNET_SHIM_ID,
        policy: parseDeploymentPolicy(values["deployment-policy"]),
        manifestPath: path.resolve(asString(values.manifest, "/tmp/psy-doge-devnet-deployment.json")),
        commitment: parseCommitment(values.commitment),
        yes: Boolean(values.yes),
    };
    return {
        profile: "local",
        dryRun: Boolean(values.preflight),
        noBuild: Boolean(values["no-build"]),
        rebuildPrograms: Boolean(values["rebuild-programs"]),
        deploy,
        teardown: false,
        purge: false,
        components: new Set<Component>(),
        projectsDir,
        bridgeRepo,
        dogecoinRepo: path.join(projectsDir, "dogecoin"),
        electrsRepo: path.join(projectsDir, "electrs-doge"),
        sp1Repo: path.join(projectsDir, "psy-bridge-sp1"),
        dogeRpcUser: "doge",
        dogeRpcPassword: "doge",
        dogecoind: false,
        deposit: false,
        withdraw: false,
    };
}

function ensureDirectory(dir: string): void {
    fs.mkdirSync(dir, { recursive: true });
}

function executableInPath(command: string): string | null {
    if (command.includes(path.sep)) {
        try {
            fs.accessSync(command, fs.constants.X_OK);
            return path.resolve(command);
        } catch {
            return null;
        }
    }
    for (const dir of (process.env.PATH || "").split(path.delimiter)) {
        const candidate = path.join(dir, command);
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
            return candidate;
        } catch {
            // Continue.
        }
    }
    return null;
}

function firstExecutable(candidates: Array<string | undefined>): string | null {
    for (const candidate of candidates) {
        if (!candidate) continue;
        const found = executableInPath(candidate);
        if (found) return found;
    }
    return null;
}

function quote(arg: string): string {
    return /^[A-Za-z0-9_./:=,@+-]+$/.test(arg) ? arg : JSON.stringify(arg);
}

function commandText(command: string[]): string {
    return command.map(quote).join(" ");
}

function fileSha256(filePath: string): string {
    const hash = createHash("sha256");
    hash.update(fs.readFileSync(filePath));
    return hash.digest("hex");
}
function writeJsonAtomic(filePath: string, value: unknown): void {
    const parent = path.dirname(filePath);
    ensureDirectory(parent);
    const temp = path.join(parent, `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`);
    fs.writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    try {
        fs.linkSync(temp, filePath);
        fs.rmSync(temp);
    } catch (error) {
        try { fs.rmSync(temp); } catch { /* Best effort. */ }
        throw error;
    }
}

function assertWritableNewPath(filePath: string): void {
    if (fs.existsSync(filePath)) fail(`Refusing to overwrite existing output: ${filePath}`);
    let parent = path.dirname(filePath);
    while (!fs.existsSync(parent)) {
        const next = path.dirname(parent);
        if (next === parent) break;
        parent = next;
    }
    fs.accessSync(parent, fs.constants.W_OK);
}


function readStartTicks(pid: number): string | null {
    try {
        const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
        const end = stat.lastIndexOf(")");
        return stat.slice(end + 2).split(" ")[19] || null;
    } catch {
        return null;
    }
}

function processMatches(record: ProcessRecord): boolean {
    return readStartTicks(record.pid) === record.startTicks;
}

function loadActiveState(): ActiveState | null {
    try {
        return JSON.parse(fs.readFileSync(ACTIVE_STATE_PATH, "utf8")) as ActiveState;
    } catch {
        return null;
    }
}

function saveActiveState(state: ActiveState): void {
    ensureDirectory(STATE_ROOT);
    const temp = `${ACTIVE_STATE_PATH}.${process.pid}.tmp`;
    fs.writeFileSync(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temp, ACTIVE_STATE_PATH);
}

function removeActiveState(): void {
    try { fs.rmSync(ACTIVE_STATE_PATH); } catch { /* Already absent. */ }
}

async function sleep(ms: number): Promise<void> {
    await Bun.sleep(ms);
}

async function portOpen(port: number, host = "127.0.0.1", timeoutMs = 350): Promise<boolean> {
    return await new Promise<boolean>((resolve) => {
        const socket = connect({ host, port });
        const timer = setTimeout(() => {
            socket.destroy();
            resolve(false);
        }, timeoutMs);
        socket.once("connect", () => {
            clearTimeout(timer);
            socket.destroy();
            resolve(true);
        });
        socket.once("error", () => {
            clearTimeout(timer);
            resolve(false);
        });
    });
}

async function jsonRpc(url: string, method: string, params: unknown[] = [], auth?: { user: string; password: string }): Promise<any> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (auth) headers.authorization = `Basic ${Buffer.from(`${auth.user}:${auth.password}`).toString("base64")}`;
    const response = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: AbortSignal.timeout(2_000),
    });
    if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`);
    const body = await response.json() as { result?: any; error?: any };
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
}

async function dogeInfo(options: Options): Promise<any | null> {
    try {
        const info = await jsonRpc(DOGE_RPC_URL, "getblockchaininfo", [], { user: options.dogeRpcUser, password: options.dogeRpcPassword });
        return info?.chain === "regtest" ? info : null;
    } catch {
        return null;
    }
}

async function solanaHealthy(): Promise<boolean> {
    try {
        return (await jsonRpc(SOLANA_RPC_URL, "getHealth")) === "ok";
    } catch {
        return false;
    }
}

async function electrsHeight(baseUrl: string = ELECTRS_HTTP_URL): Promise<number | null> {
    try {
        const response = await fetch(`${baseUrl.replace(/\/$/, "")}/blocks/tip/height`, { signal: AbortSignal.timeout(10_000) });
        if (!response.ok) return null;
        const height = Number.parseInt((await response.text()).trim(), 10);
        return Number.isFinite(height) ? height : null;
    } catch {
        return null;
    }
}

async function electrsText(baseUrl: string, route: string): Promise<string> {
    const url = `${baseUrl.replace(/\/$/, "")}${route.startsWith("/") ? route : `/${route}`}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!response.ok) fail(`Electrs ${url} returned ${response.status}: ${await response.text()}`);
    return (await response.text()).trim();
}


type FundingUtxo = {
    txid: string;
    vout: number;
    value: number;
    status: { confirmed: boolean; block_height?: number };
};

function fundingP2pkhScriptHash(address: string): string {
    const decoded = Uint8Array.from(bs58.decode(address));
    if (decoded.length !== 25) fail(`Funding address ${address} must decode to 25 bytes.`);
    const body = decoded.slice(0, 21);
    const checksum = decoded.slice(21);
    const first = createHash("sha256").update(body).digest();
    const expected = createHash("sha256").update(first).digest().subarray(0, 4);
    if (!Buffer.from(checksum).equals(expected)) fail(`Funding address ${address} has an invalid Base58Check checksum.`);
    if (decoded[0] !== REGTEST_P2PKH_VERSION) {
        fail(`Funding address ${address} is not regtest P2PKH (version 0x${decoded[0].toString(16)}).`);
    }
    const script = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), Buffer.from(decoded.slice(1, 21)), Buffer.from([0x88, 0xac])]);
    return createHash("sha256").update(script).digest("hex");
}

async function fundingUtxos(address: string, electrsBaseUrl: string = ELECTRS_HTTP_URL): Promise<FundingUtxo[]> {
    const scriptHash = fundingP2pkhScriptHash(address);
    const response = await fetch(`${electrsBaseUrl.replace(/\/$/, "")}/scripthash/${scriptHash}/utxo`, { signal: AbortSignal.timeout(15_000) });
    if (!response.ok) fail(`Electrs funding UTXO query returned ${response.status}: ${await response.text()}`);
    const value: unknown = await response.json();
    if (!Array.isArray(value)) fail("Electrs funding UTXO response must be an array.");
    return value.map((entry, index) => {
        if (typeof entry !== "object" || entry === null || Array.isArray(entry)) fail(`Electrs funding UTXO ${index} must be an object.`);
        const object = entry as Record<string, unknown>;
        const status = object.status;
        if (typeof status !== "object" || status === null || Array.isArray(status)) fail(`Electrs funding UTXO ${index}.status must be an object.`);
        const statusObject = status as Record<string, unknown>;
        if (typeof object.txid !== "string" || !/^[0-9a-f]{64}$/i.test(object.txid)) fail(`Electrs funding UTXO ${index}.txid is invalid.`);
        if (!Number.isInteger(object.vout) || Number(object.vout) < 0) fail(`Electrs funding UTXO ${index}.vout is invalid.`);
        if (!Number.isSafeInteger(object.value) || Number(object.value) <= 0) fail(`Electrs funding UTXO ${index}.value is invalid.`);
        if (typeof statusObject.confirmed !== "boolean") fail(`Electrs funding UTXO ${index}.status.confirmed must be boolean.`);
        if (statusObject.block_height !== undefined && (!Number.isInteger(statusObject.block_height) || Number(statusObject.block_height) < 0)) {
            fail(`Electrs funding UTXO ${index}.status.block_height is invalid.`);
        }
        return {
            txid: object.txid,
            vout: Number(object.vout),
            value: Number(object.value),
            status: { confirmed: statusObject.confirmed, block_height: statusObject.block_height === undefined ? undefined : Number(statusObject.block_height) },
        };
    });
}

async function waitFor<T>(name: string, timeoutMs: number, probe: () => Promise<T | null | false>): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    let lastError: unknown;
    while (Date.now() < deadline) {
        try {
            const value = await probe();
            if (value !== null && value !== false) return value as T;
        } catch (error) {
            lastError = error;
        }
        await sleep(500);
    }
    throw new Error(`Timed out waiting for ${name}${lastError ? `: ${String(lastError)}` : ""}`);
}

class Launcher {
    readonly options: Options;
    readonly runId: string;
    readonly runDir: string;
    readonly state: ActiveState;
    readonly programs: Program[];
    shuttingDown = false;
    bridgeCheckpoint: { configPath: string; height: number; hash: string } | null = null;

    constructor(options: Options) {
        this.options = options;
        this.runId = `${new Date().toISOString().replace(/[:.]/g, "-")}-${process.pid}`;
        this.runDir = path.join(STATE_ROOT, "runs", this.runId);
        this.state = {
            version: 1,
            runId: this.runId,
            createdAt: new Date().toISOString(),
            runDir: this.runDir,
            processes: [],
            containers: [],
        };
        const keyDir = path.join(options.bridgeRepo, "tests/local-network-tests/program-keys");
        const elfDir = path.join(options.bridgeRepo, "target/sbpf-solana-solana/release");
        this.programs = [
            { name: "doge-bridge", keypair: path.join(keyDir, "doge-bridge.json"), elf: path.join(elfDir, "doge_bridge.so") },
            { name: "pending-mint-buffer", keypair: path.join(keyDir, "pending-mint.json"), elf: path.join(elfDir, "pending_mint_buffer.so") },
            { name: "txo-buffer", keypair: path.join(keyDir, "txo-buffer.json"), elf: path.join(elfDir, "txo_buffer.so") },
            { name: "generic-buffer", keypair: path.join(keyDir, "generic-buffer.json"), elf: path.join(elfDir, "generic_buffer.so") },
            { name: "manual-claim", keypair: path.join(keyDir, "manual-claim.json"), elf: path.join(elfDir, "manual_claim.so") },
            { name: "noop-shim", keypair: path.join(keyDir, "noop-shim.json"), elf: path.join(elfDir, "noop_shim.so") },
        ];
        if (!options.deploy) {
            this.programs.push({
                name: "delegated-manager-set",
                id: DELEGATED_MANAGER_SET_ID,
                elf: path.join(elfDir, "delegated_manager_set.so"),
            });
        }
        if (options.deploy) {
            const filenames: Record<string, string> = {
                "doge-bridge": "doge-bridge.json",
                "pending-mint-buffer": "pending-mint.json",
                "txo-buffer": "txo-buffer.json",
                "generic-buffer": "generic-buffer.json",
                "manual-claim": "manual-claim.json",
            };
            this.programs = this.programs.filter((program) => program.name !== "noop-shim");
            for (const program of this.programs) {
                const explicit = options.deploy.programKeypairs[program.name];
                if (explicit) program.keypair = explicit;
                else if (options.deploy.programKeyDir) program.keypair = path.join(options.deploy.programKeyDir, filenames[program.name]);
            }
        }
    }

    persist(): void {
        saveActiveState(this.state);
    }

    removeProcess(pid: number): void {
        this.state.processes = this.state.processes.filter((record) => record.pid !== pid);
        if (this.shuttingDown) return;
        if (this.state.processes.length === 0 && this.state.containers.length === 0) removeActiveState();
        else this.persist();
    }

    async spawn(command: string[], role: string, cwd: string | undefined, daemon: boolean, env: Record<string, string> = {}): Promise<Bun.Subprocess> {
        ensureDirectory(this.runDir);
        const safeRole = role.replace(/[^A-Za-z0-9_.-]/g, "-");
        const stdoutLog = path.join(this.runDir, `${safeRole}.stdout.log`);
        const stderrLog = path.join(this.runDir, `${safeRole}.stderr.log`);
        fs.writeFileSync(stdoutLog, "", { mode: 0o600 });
        fs.writeFileSync(stderrLog, "", { mode: 0o600 });
        console.log(`[start:${role}] ${commandText(command)}`);
        const processCwd = cwd || CLI_REPO;
        const proc = Bun.spawn(command, {
            cwd: processCwd,
            env: { ...process.env, NO_PROXY: "localhost,127.0.0.1", no_proxy: "localhost,127.0.0.1", ...env },
            stdout: Bun.file(stdoutLog),
            stderr: Bun.file(stderrLog),
        });
        const startTicks = await waitFor<string>(`${role} PID registration`, 2_000, async () => readStartTicks(proc.pid));
        const record: ProcessRecord = { role, pid: proc.pid, startTicks, command, cwd: processCwd, stdoutLog, stderrLog };
        this.state.processes.push(record);
        this.persist();
        void proc.exited.then((code) => {
            this.removeProcess(proc.pid);
            if (daemon && !this.shuttingDown && code !== 0) {
                console.error(`[fatal] ${role} exited with code ${code}. Logs: ${stderrLog}`);
                void this.cleanup(false).finally(() => process.exit(1));
            }
        });
        return proc;
    }

    async run(command: string[], role: string, cwd: string): Promise<string> {
        const proc = await this.spawn(command, role, cwd, false);
        const code = await proc.exited;
        const record = this.state.processes.find((item) => item.pid === proc.pid);
        const stdoutLog = record?.stdoutLog || path.join(this.runDir, `${role}.stdout.log`);
        const stderrLog = record?.stderrLog || path.join(this.runDir, `${role}.stderr.log`);
        const stdout = fs.existsSync(stdoutLog) ? fs.readFileSync(stdoutLog, "utf8") : "";
        const stderr = fs.existsSync(stderrLog) ? fs.readFileSync(stderrLog, "utf8") : "";
        if (code !== 0) {
            throw new Error(`${role} failed (${code}): ${commandText(command)}\n${stderr || stdout}\nLogs: ${stdoutLog}, ${stderrLog}`);
        }
        return stdout.trim();
    }

    async cleanup(removeData: boolean): Promise<void> {
        if (this.shuttingDown) return;
        this.shuttingDown = true;
        const state = loadActiveState() || this.state;
        for (const container of [...state.containers].reverse()) {
            console.log(`[stop:${container.role}] docker rm -f ${container.id}`);
            Bun.spawnSync(["docker", "rm", "-f", container.id], { stdout: "ignore", stderr: "ignore" });
        }
        const records = [...state.processes].reverse();
        for (const record of records) {
            if (!processMatches(record)) {
                console.warn(`[skip:${record.role}] PID ${record.pid} no longer matches its recorded Linux start time.`);
                continue;
            }
            console.log(`[stop:${record.role}] SIGTERM ${record.pid}`);
            try { process.kill(record.pid, "SIGTERM"); } catch { /* Already stopped. */ }
        }
        const deadline = Date.now() + 8_000;
        while (Date.now() < deadline && records.some(processMatches)) await sleep(200);
        for (const record of records) {
            if (!processMatches(record)) continue;
            console.warn(`[stop:${record.role}] SIGKILL ${record.pid} after graceful timeout`);
            try { process.kill(record.pid, "SIGKILL"); } catch { /* Already stopped. */ }
        }
        removeActiveState();
        if (removeData) {
            fs.rmSync(STATE_ROOT, { recursive: true, force: true });
            console.log(`[purge] Removed ${STATE_ROOT}`);
        }
    }

    async resolveProgramIds(): Promise<void> {
        const keygen = executableInPath("solana-keygen");
        if (!keygen) fail("Missing solana-keygen. Install the Solana/Agave CLI tools.");
        for (const program of this.programs) {
            if (program.id) continue;
            if (!program.keypair || !fs.existsSync(program.keypair)) fail(`Missing program keypair: ${program.keypair ?? program.name}`);
            const result = Bun.spawnSync([keygen, "pubkey", program.keypair], { stdout: "pipe", stderr: "pipe" });
            if (result.exitCode !== 0) fail(`Invalid program keypair ${program.keypair}: ${result.stderr.toString()}`);
            program.id = result.stdout.toString().trim();
        }
    }

    findDogeBinaries(): { daemon: string | null; cli: string | null } {
        return {
            daemon: firstExecutable([
                process.env.DOGECOIND,
                "dogecoind",
                path.join(this.options.dogecoinRepo, "src/dogecoind"),
                path.join(this.options.dogecoinRepo, "build/src/dogecoind"),
            ]),
            cli: firstExecutable([
                process.env.DOGECOIN_CLI,
                "dogecoin-cli",
                path.join(this.options.dogecoinRepo, "src/dogecoin-cli"),
                path.join(this.options.dogecoinRepo, "build/src/dogecoin-cli"),
            ]),
        };
    }

    findElectrsBinary(): string | null {
        return firstExecutable([
            process.env.ELECTRS_DOGE,
            "electrs-doge",
            path.join(this.options.electrsRepo, "target/release/electrs"),
        ]);
    }

    bridgeBuildCommands(): string[][] {
        // BridgeTestnetVk: workspace post-processing breaks with `cargo build-sbf -- -p ...`.
        // Prefer package-scoped --manifest-path for doge-bridge and space-separated features.
        if (this.options.deploy) {
            return [
                [
                    "cargo", "build-sbf",
                    "--manifest-path", "programs/doge-bridge/Cargo.toml",
                    "--no-default-features",
                    "--features", "solprogram", "wormhole", "testnet-vk",
                ],
                ["cargo", "build-sbf", "--manifest-path", "programs/manual-claim/Cargo.toml", "--no-default-features", "--features", "solprogram"],
                ["cargo", "build-sbf", "--manifest-path", "programs/pending-mint-buffer/Cargo.toml", "--no-default-features"],
                ["cargo", "build-sbf", "--manifest-path", "programs/txo-buffer/Cargo.toml", "--no-default-features"],
                ["cargo", "build-sbf", "--manifest-path", "programs/generic-buffer/Cargo.toml", "--no-default-features"],
            ];
        }
        const shimFeature = "noopshim";
        const networkVkFeature = "regtest-vk";
        return [
            [
                "cargo", "build-sbf",
                "--manifest-path", "programs/doge-bridge/Cargo.toml",
                "--no-default-features",
                "--features", "solprogram", shimFeature, networkVkFeature,
            ],
            ["cargo", "build-sbf", "--manifest-path", "programs/manual-claim/Cargo.toml", "--no-default-features", "--features", "solprogram"],
            ["cargo", "build-sbf", "--manifest-path", "programs/pending-mint-buffer/Cargo.toml", "--no-default-features"],
            ["cargo", "build-sbf", "--manifest-path", "programs/txo-buffer/Cargo.toml", "--no-default-features"],
            ["cargo", "build-sbf", "--manifest-path", "programs/generic-buffer/Cargo.toml", "--no-default-features"],
            ["cargo", "build-sbf", "--manifest-path", "programs/noop-shim/Cargo.toml", "--no-default-features"],
            ["cargo", "build-sbf", "--manifest-path", "programs/delegated-manager-set/Cargo.toml", "--no-default-features"],
        ];
    }

    dogeCommand(daemon: string): string[] {
        return [
            daemon,
            "-regtest=1",
            "-server=1",
            "-listen=1",
            `-port=${PORTS.dogeP2p}`,
            `-rpcport=${PORTS.dogeRpc}`,
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            `-rpcuser=${this.options.dogeRpcUser}`,
            `-rpcpassword=${this.options.dogeRpcPassword}`,
            `-datadir=${DOGE_DATA_DIR}`,
            "-txindex=1",
            "-fallbackfee=0.01",
            "-printtoconsole=1",
        ];
    }

    electrsCommand(binary: string): string[] {
        return [
            binary,
            "--network", "regtest",
            "--daemon-dir", DOGE_DATA_DIR,
            "--daemon-rpc-addr", `127.0.0.1:${PORTS.dogeRpc}`,
            "--cookie", `${this.options.dogeRpcUser}:${this.options.dogeRpcPassword}`,
            "--db-dir", ELECTRS_DATA_DIR,
            "--http-addr", `127.0.0.1:${PORTS.electrsHttp}`,
            "--electrum-rpc-addr", `127.0.0.1:${PORTS.electrum}`,
            "--monitoring-addr", `127.0.0.1:${PORTS.electrsMetrics}`,
            "--jsonrpc-import",
            "-vv",
        ];
    }

    solanaCommand(): string[] {
        const command = [
            "solana-test-validator",
            "--ledger", SOLANA_LEDGER_DIR,
            "--bind-address", "127.0.0.1",
            "--gossip-host", "127.0.0.1",
            "--rpc-port", String(PORTS.solanaRpc),
            "--faucet-port", String(PORTS.solanaFaucet),
            "--compute-unit-limit", "1400000",
        ];
        for (const program of this.programs) command.push("--bpf-program", program.id ?? program.keypair!, program.elf);
        return command;
    }

    syncOutput(command: string[], cwd: string): { ok: boolean; stdout: string; stderr: string } {
        const result = Bun.spawnSync(command, { cwd, stdout: "pipe", stderr: "pipe" });
        return {
            ok: result.exitCode === 0,
            stdout: result.stdout.toString().trim(),
            stderr: result.stderr.toString().trim(),
        };
    }



    deploymentCommand(program: Program): string[] {
        const deploy = this.options.deploy!;
        if (!program.keypair) fail(`Missing deployment keypair for ${program.name}`);
        return [
            "solana", "program", "deploy",
            "--url", deploy.rpcUrl,
            "--commitment", deploy.commitment,
            "--keypair", deploy.payerKeypair,
            "--upgrade-authority", deploy.upgradeAuthorityKeypair,
            "--program-id", program.keypair,
            program.elf,
        ];
    }

    capture(command: string[], cwd = this.options.bridgeRepo): string {
        const result = Bun.spawnSync(command, { cwd, stdout: "pipe", stderr: "pipe" });
        if (result.exitCode !== 0) fail(`${commandText(command)} failed: ${result.stderr.toString().trim() || result.stdout.toString().trim()}`);
        return result.stdout.toString().trim();
    }

    keypairPubkey(keypair: string): string {
        return this.capture(["solana-keygen", "pubkey", keypair], CLI_REPO);
    }

    async deploymentAccount(id: string): Promise<any | null> {
        const deploy = this.options.deploy!;
        const result = await jsonRpc(deploy.rpcUrl, "getAccountInfo", [id, { encoding: "base64", commitment: deploy.commitment }]);
        return result?.value || null;
    }

    programShow(id: string): Record<string, string> {
        const deploy = this.options.deploy!;
        const output = this.capture(["solana", "program", "show", id, "--url", deploy.rpcUrl, "--output", "json"], CLI_REPO);
        return JSON.parse(output) as Record<string, string>;
    }

    async preflightDeployment(): Promise<{ genesisHash: string; solanaVersion: string; payerPubkey: string; balanceLamports: number; actions: Record<string, "deploy" | "upgrade"> }> {
        const deploy = this.options.deploy!;
        const errors: string[] = [];
        if (!fs.existsSync(this.options.bridgeRepo)) errors.push(`Missing bridge repository: ${this.options.bridgeRepo}`);
        for (const tool of ["solana", "solana-keygen"]) if (!executableInPath(tool)) errors.push(`Missing required command '${tool}'.`);
        for (const keypair of [deploy.payerKeypair, deploy.upgradeAuthorityKeypair]) if (!fs.existsSync(keypair)) errors.push(`Missing keypair: ${keypair}`);
        if (!deploy.programKeyDir && PUBLIC_PROGRAM_NAMES.some((name) => !deploy.programKeypairs[name])) errors.push("Supply --program-key-dir or every individual public program keypair.");
        for (const program of this.programs) if (!program.keypair || !fs.existsSync(program.keypair)) errors.push(`Missing program keypair: ${program.keypair ?? program.name}`);
        try { assertWritableNewPath(deploy.manifestPath); } catch (error) { errors.push(`Manifest path is not safely writable: ${String(error)}`); }
        const missingElfs = this.programs.filter((program) => !fs.existsSync(program.elf));
        if ((missingElfs.length > 0 || this.options.rebuildPrograms) && this.options.noBuild) errors.push(`Public build required but --no-build was set: ${missingElfs.map((p) => p.elf).join(", ") || "--rebuild-programs"}`);
        if (!this.options.noBuild) {
            for (const tool of ["cargo", "cargo-build-sbf"]) if (!executableInPath(tool)) errors.push(`Public build requires '${tool}'.`);
        }
        const provenancePath = path.join(path.dirname(this.programs[0].elf), "doge-public-build.json");
        if (this.options.noBuild) {
            if (!fs.existsSync(provenancePath)) errors.push(`--no-build requires trusted public build provenance: ${provenancePath}`);
            else {
                try {
                    const provenance = JSON.parse(fs.readFileSync(provenancePath, "utf8")) as { features?: unknown; programs?: Record<string, { sha256?: string }> };
                    if (provenance.features !== "solprogram,wormhole; no defaults; no mock-zkp; no noop-shim") errors.push(`Invalid public build feature provenance in ${provenancePath}`);
                    for (const program of this.programs) if (fs.existsSync(program.elf) && provenance.programs?.[program.name]?.sha256 !== fileSha256(program.elf)) errors.push(`ELF hash does not match trusted public provenance for ${program.name}.`);
                } catch (error) { errors.push(`Cannot validate public build provenance ${provenancePath}: ${String(error)}`); }
            }
        }
        if (!this.options.dryRun && !deploy.yes) errors.push("Public network mutation requires explicit --yes. Use --preflight for a read-only plan.");
        if (errors.length > 0) fail(`Deployment preflight failed before network mutation:\n  - ${errors.join("\n  - ")}`);

        await this.resolveProgramIds();
        const payerPubkey = this.keypairPubkey(deploy.payerKeypair);
        const authorityPubkey = this.keypairPubkey(deploy.upgradeAuthorityKeypair);
        for (const program of this.programs) if ([deploy.wormholeCoreId, deploy.wormholeShimId, LOCAL_NOOP_SHIM_ID].includes(program.id!)) fail(`Custom program ${program.name} collides with canonical/local-only program ID ${program.id}.`);
        for (const program of this.programs) {
            const expected = PUBLIC_PROGRAM_IDS[program.name as keyof typeof PUBLIC_PROGRAM_IDS];
            if (expected && program.id !== expected) {
                fail(`Program keypair for ${program.name} derives ${program.id}, expected canonical ${expected}.`);
            }
        }
        const genesisHash = String(await jsonRpc(deploy.rpcUrl, "getGenesisHash"));
        const versionResult = await jsonRpc(deploy.rpcUrl, "getVersion");
        const solanaVersion = String(versionResult?.["solana-core"] || versionResult?.["agave-core"] || "unknown");
        if (deploy.cluster === "devnet" && genesisHash !== SOLANA_GENESIS_HASHES.devnet) fail(`RPC genesis ${genesisHash} is not Solana devnet ${SOLANA_GENESIS_HASHES.devnet}.`);
        const balanceLamports = Number(await jsonRpc(deploy.rpcUrl, "getBalance", [payerPubkey, { commitment: deploy.commitment }]).then((value) => value?.value));
        if (!Number.isFinite(balanceLamports)) fail("Could not determine payer balance.");
        const estimatedLamports = this.programs.reduce(
            (sum, program) => sum + (fs.existsSync(program.elf) ? fs.statSync(program.elf).size * 20 : 2_000_000),
            0,
        ) + 5_000_000_000;
        if (balanceLamports < estimatedLamports) fail(`Payer balance is ${(balanceLamports / 1e9).toFixed(3)} SOL, below conservative deployment estimate ${(estimatedLamports / 1e9).toFixed(3)} SOL.`);
        for (const [label, id] of [["Core", deploy.wormholeCoreId], ["shim", deploy.wormholeShimId]] as const) {
            const account = await this.deploymentAccount(id);
            if (!account?.executable) fail(`Canonical Wormhole ${label} ${id} is absent or not executable at ${deploy.rpcUrl}.`);
        }
        const actions: Record<string, "deploy" | "upgrade"> = {};
        for (const program of this.programs) {
            const account = await this.deploymentAccount(program.id!);
            if (!account) {
                if (deploy.policy === "upgrade") fail(`${program.name} ${program.id} does not exist but policy is upgrade.`);
                actions[program.name] = "deploy";
                continue;
            }
            if (!account.executable || account.owner !== UPGRADEABLE_LOADER_ID) fail(`${program.name} ${program.id} exists with unexpected executable/owner state (${account.owner}).`);
            if (deploy.policy === "new") fail(`${program.name} ${program.id} already exists but policy is new.`);
            const show = this.programShow(program.id!);
            const actualAuthority = String(show.authority || show.upgradeAuthority || "");
            if (actualAuthority !== authorityPubkey) fail(`${program.name} upgrade authority mismatch: expected ${authorityPubkey}, found ${actualAuthority || "none"}.`);
            actions[program.name] = "upgrade";
        }
        console.log(`[deploy] cluster=${deploy.cluster} rpc=${deploy.rpcUrl} genesis=${genesisHash} solana=${solanaVersion}`);
        console.log(`[deploy] payer=${payerPubkey} balance=${(balanceLamports / 1e9).toFixed(3)} SOL policy=${deploy.policy}`);
        console.log(`[deploy] canonical Core=${deploy.wormholeCoreId} shim=${deploy.wormholeShimId}`);
        console.log("\n[deployment plan]");
        if (!this.options.noBuild) for (const command of this.bridgeBuildCommands()) console.log(`  (build non-mock) ${commandText(command)}`);
        if (this.options.noBuild) console.log("  (build reuse) trusted doge-public-build.json hashes and exact solprogram,wormhole feature set");
        for (const program of this.programs) console.log(`  (${actions[program.name]}) ${commandText(this.deploymentCommand(program))}`);
        for (const program of this.programs) console.log(`  (verify) solana program dump ${program.id} <dump> --url ${deploy.rpcUrl}; SHA-256 == ${program.elf}`);
        console.log(`  (manifest atomic) ${deploy.manifestPath}\n`);
        return { genesisHash, solanaVersion, payerPubkey, balanceLamports, actions };
    }

    async deployPublic(): Promise<void> {
        const deploy = this.options.deploy!;
        const preflight = await this.preflightDeployment();
        if (this.options.dryRun) {
            console.log("[preflight] PASS — all public deployment checks completed and exact non-mutating plan printed; no build/deploy/init subprocess was spawned.");
            return;
        }
        ensureDirectory(this.runDir);
        const commandStatus: Array<{ operation: string; program?: string; status: string }> = [];
        if (!this.options.noBuild) {
            for (const [index, command] of this.bridgeBuildCommands().entries()) {
                await this.run(command, `public-build-${index + 1}`, this.options.bridgeRepo);
                commandStatus.push({ operation: "build", program: this.programs[index]?.name, status: "built" });
            }
            const provenancePath = path.join(path.dirname(this.programs[0].elf), "doge-public-build.json");
            const temp = `${provenancePath}.${process.pid}.tmp`;
            fs.writeFileSync(temp, `${JSON.stringify({
                timestamp: new Date().toISOString(),
                features: "solprogram,wormhole; no defaults; no mock-zkp; no noop-shim",
                operations: this.bridgeBuildCommands().map((_command, index) => ({ operation: "build", program: this.programs[index]?.name })),
                programs: Object.fromEntries(this.programs.map((program) => [program.name, { sha256: fileSha256(program.elf) }])),
            }, null, 2)}\n`, { mode: 0o600 });
            fs.renameSync(temp, provenancePath);
            commandStatus.push({ operation: "write-build-provenance", status: "built" });
        }
        for (const program of this.programs) if (!fs.existsSync(program.elf)) fail(`Public build did not produce ${program.elf}`);
        for (const program of this.programs) {
            const command = this.deploymentCommand(program);
            await this.run(command, `${preflight.actions[program.name]}-${program.name}`, this.options.bridgeRepo);
            commandStatus.push({ operation: preflight.actions[program.name], program: program.name, status: preflight.actions[program.name] });
        }
        const deployedPrograms: Record<string, unknown> = {};
        for (const program of this.programs) {
            const dumpPath = path.join(this.runDir, `${program.name}-deployed.so`);
            await this.run(["solana", "program", "dump", program.id!, dumpPath, "--url", deploy.rpcUrl], `dump-${program.name}`, this.options.bridgeRepo);
            commandStatus.push({ operation: "verify-dump", program: program.name, status: "verified" });
            const localSha256 = fileSha256(program.elf);
            const deployedSha256 = fileSha256(dumpPath);
            if (localSha256 !== deployedSha256) fail(`${program.name} deployed ELF hash ${deployedSha256} does not match local ${localSha256}. Manifest not written.`);
            const account = await jsonRpc(deploy.rpcUrl, "getAccountInfo", [program.id, { encoding: "base64", commitment: deploy.commitment }]);
            deployedPrograms[program.name] = { id: program.id, action: preflight.actions[program.name], localSha256, deployedSha256, slot: account?.context?.slot };
        }
        const bridgeState = await jsonRpc(deploy.rpcUrl, "getAccountInfo", [BRIDGE_STATE_PDA, { encoding: "base64", commitment: deploy.commitment }]);
        writeJsonAtomic(deploy.manifestPath, {
            schemaVersion: 1,
            timestamp: new Date().toISOString(),
            cluster: deploy.cluster,
            genesisHash: preflight.genesisHash,
            rpcUrl: deploy.rpcUrl,
            solanaVersion: preflight.solanaVersion,
            commitment: deploy.commitment,
            payerPubkey: preflight.payerPubkey,
            featureSet: { dogeBridge: ["solprogram", "wormhole"], defaultFeatures: false, mockZkp: false, noopShim: false },
            canonicalWormhole: { coreId: deploy.wormholeCoreId, shimId: deploy.wormholeShimId, source: "wormhole svm/wormhole-core-shims/crates/definitions/src/solana.rs or explicit operator input" },
            programs: deployedPrograms,
            bridgeState: { pda: BRIDGE_STATE_PDA, present: Boolean(bridgeState?.value), slot: bridgeState?.context?.slot },
            commands: commandStatus,
            status: "verified",
        });
        console.log(`[deploy] PASS — verified ${this.programs.length} custom programs; atomic manifest ${deploy.manifestPath}`);
    }


    async preflight(): Promise<{ dogeRunning: boolean; solanaRunning: boolean; electrsRunning: boolean }> {
        const c = this.options.components;
        console.log(`[profile] ${this.options.profile}`);
        console.log(`[components] ${[...c].join(", ") || "none"}`);
        console.log(`[state] ${STATE_ROOT}`);


        if (c.has("dogecoin") && !fs.existsSync(this.options.dogecoinRepo)) fail(`Missing Dogecoin repository: ${this.options.dogecoinRepo}`);
        if (c.has("electrs") && !fs.existsSync(this.options.electrsRepo)) fail(`Missing electrs-doge repository: ${this.options.electrsRepo}`);
        if (c.has("block-sender") && !fs.existsSync(path.join(this.options.projectsDir, "solana-doge-bridge-block-sender"))) fail(`Missing block sender repository: ${path.join(this.options.projectsDir, "solana-doge-bridge-block-sender")}`);
        if (c.has("ibc-pipeline") && !fs.existsSync(path.join(this.options.projectsDir, "solana-doge-ibc"))) fail(`Missing IBC repository: ${path.join(this.options.projectsDir, "solana-doge-ibc")}`);
        if (c.has("manager-service") && !fs.existsSync(this.localOpsRoot())) fail(`Missing local operator repository: ${this.localOpsRoot()}`);
        if (c.has("solana") && !fs.existsSync(this.options.bridgeRepo)) fail(`Missing bridge repository: ${this.options.bridgeRepo}`);
        if ((c.has("solana") || c.has("initialize") || c.has("noop-monitor")) && !fs.existsSync(this.options.sp1Repo)) fail(`Missing SP1 repository: ${this.options.sp1Repo}`);
        if (this.options.localSmokeFundingArtifact) {
            try { assertWritableNewPath(this.options.localSmokeFundingArtifact); } catch (error) { fail(`Local smoke funding artifact path is not safely writable: ${String(error)}`); }
        }

        const requiredTools = new Set<string>();
        if (c.has("block-sender")) requiredTools.add("node");
        if (c.has("ibc-pipeline")) {
            requiredTools.add("cargo");
            requiredTools.add("docker");
        }
        if (c.has("solana")) ["solana", "solana-keygen", "solana-test-validator"].forEach((tool) => requiredTools.add(tool));
        for (const tool of requiredTools) if (!executableInPath(tool)) fail(`Missing required command '${tool}'.`);

        let missingElfs: Program[] = [];
        if (c.has("solana")) {
            await this.resolveProgramIds();
            missingElfs = this.programs.filter((program) => !fs.existsSync(program.elf));
            if (missingElfs.length > 0 || this.options.rebuildPrograms) {
                if (this.options.noBuild) fail(`Bridge ELF build required but --no-build was set: ${missingElfs.map((p) => p.elf).join(", ")}`);
                if (!executableInPath("cargo") || !executableInPath("cargo-build-sbf")) fail("Building bridge ELFs requires cargo and cargo-build-sbf.");
            }
        }

        const dogeRunning = c.has("dogecoin") ? Boolean(await dogeInfo(this.options)) : false;
        const solanaRunning = c.has("solana") ? await solanaHealthy() : false;
        const indexedHeight = c.has("electrs") ? await electrsHeight() : null;
        const electrsRunning = indexedHeight !== null;

        const dogeBinaries = this.findDogeBinaries();
        if (c.has("dogecoin") && !dogeRunning && (!dogeBinaries.daemon || !dogeBinaries.cli)) {
            if (this.options.noBuild) fail("dogecoind/dogecoin-cli are missing and --no-build was set.");
            for (const tool of ["make", "autoreconf"]) if (!executableInPath(tool)) fail(`Building Dogecoin Core requires '${tool}'.`);
        }
        const electrsBinary = this.findElectrsBinary();
        if (c.has("electrs") && !electrsRunning && !electrsBinary) {
            if (this.options.noBuild) fail("electrs-doge is missing and --no-build was set.");
            if (!executableInPath("cargo")) fail("Building electrs-doge requires cargo.");
        }
        if (c.has("block-sender") && !fs.existsSync(path.join(this.options.projectsDir, "solana-doge-bridge-block-sender", "apps", "sol-send-server", "dist", "index.js"))) {
            console.warn("[block-sender] dist/index.js is missing; startup will skip the sender until its TypeScript app is built.");
        }
        if (c.has("manager-service") && !firstExecutable([this.localOpsCli()])) {
            if (this.options.noBuild) fail(`doge-solana-cli is missing and --no-build was set: ${this.localOpsCli()}`);
            if (!executableInPath("cargo")) fail("Building doge-solana-cli requires cargo.");
        }

        if (c.has("solana")) {
            const genProof = path.join(this.options.sp1Repo, "target/release/gen-proof");
            if (!firstExecutable([genProof])) {
                if (this.options.noBuild) fail(`SP1 block prover is missing and --no-build was set: ${genProof}`);
                if (!executableInPath("cargo")) fail("Building the SP1 block prover requires cargo.");
            }
        }

        const dogeRpcOpen = await portOpen(PORTS.dogeRpc);
        const dogeP2pOpen = await portOpen(PORTS.dogeP2p);
        if (c.has("dogecoin")) {
            if (dogeRpcOpen && !dogeRunning) fail(`Port ${PORTS.dogeRpc} is occupied by a service that is not compatible Dogecoin regtest RPC.`);
            if (!dogeRunning && dogeP2pOpen) fail(`Dogecoin P2P port ${PORTS.dogeP2p} is already occupied.`);
            if (dogeRunning && !dogeP2pOpen) console.warn(`[dogecoin] Existing compatible regtest RPC has no listener on configured P2P port ${PORTS.dogeP2p}; reusing RPC without requiring that optional listener.`);
        }

        const solanaPorts = await Promise.all([portOpen(PORTS.solanaRpc), portOpen(PORTS.solanaWs), portOpen(PORTS.solanaFaucet)]);
        if (c.has("solana")) {
            if (solanaPorts[0] && !solanaRunning) fail(`Port ${PORTS.solanaRpc} is occupied by a service that is not healthy Solana RPC.`);
            if (!solanaRunning && solanaPorts.some(Boolean)) fail(`One or more Solana ports (${PORTS.solanaRpc}/${PORTS.solanaWs}/${PORTS.solanaFaucet}) are occupied.`);
            if (solanaRunning && (!solanaPorts[1] || !solanaPorts[2])) fail("Existing Solana RPC is healthy but its websocket or faucet port is missing.");
        }

        const electrsPorts = await Promise.all([portOpen(PORTS.electrsHttp), portOpen(PORTS.electrum), portOpen(PORTS.electrsMetrics)]);
        if (c.has("electrs")) {
            if (electrsPorts[0] && !electrsRunning) fail(`Port ${PORTS.electrsHttp} is occupied by a service that is not compatible electrs HTTP.`);
            if (!electrsRunning && electrsPorts.some(Boolean)) fail(`One or more electrs ports (${PORTS.electrsHttp}/${PORTS.electrum}/${PORTS.electrsMetrics}) are occupied.`);
            if (electrsRunning && (!electrsPorts[1] || !electrsPorts[2])) fail("Existing electrs HTTP is healthy but Electrum or metrics is not listening.");
        }
        if (c.has("block-sender") && await portOpen(BLOCK_SENDER_PORT)) fail(`Block sender port ${BLOCK_SENDER_PORT} is already occupied; it is never adopted or killed.`);
        if (c.has("manager-service") && await portOpen(MANAGER_SERVICE_PORT)) fail(`Manager service port ${MANAGER_SERVICE_PORT} is already occupied; it is never adopted or killed.`);

        if (solanaRunning) await this.verifyProgramAccounts(false);

        console.log("\n[plan]");
        if (c.has("dogecoin")) {
            const daemon = dogeBinaries.daemon || path.join(this.options.dogecoinRepo, "src/dogecoind");
            if (!dogeBinaries.daemon || !dogeBinaries.cli) {
                console.log(`  (build) ${path.join(this.options.dogecoinRepo, "autogen.sh")}`);
                console.log(`  (build) ${path.join(this.options.dogecoinRepo, "configure")} --without-gui --disable-tests --disable-bench`);
                console.log(`  (build) make -j${Math.max(1, os.availableParallelism())} src/dogecoind src/dogecoin-cli`);
            }
            console.log(`  ${dogeRunning ? "(reuse)" : "(start)"} ${commandText(this.dogeCommand(daemon))}`);
            console.log("  (ready) getblockchaininfo.chain == regtest; mine to height 101 when lower");
        }
        if (c.has("electrs")) {
            const binary = electrsBinary || path.join(this.options.electrsRepo, "target/release/electrs");
            if (!electrsBinary) console.log("  (build) cargo build --release --bin electrs");
            console.log(`  ${electrsRunning ? "(reuse)" : "(start)"} ${commandText(this.electrsCommand(binary))}`);
            console.log("  (ready) /blocks/tip/height equals Dogecoin getblockcount");
        }
        if (this.options.localSmokeFundingArtifact) {
            console.log(`  (prepare local smoke funding) getnewaddress; generatetoaddress ${LOCAL_SMOKE_FUNDING_BLOCKS}; wait for Electrs tip equality; write mode-600 ${this.options.localSmokeFundingArtifact}`);
            console.log("  (ordering) funding preparation completes before dynamic checkpoint generation and bridge initialization");
        }
        if (c.has("solana")) {
            if (missingElfs.length > 0 || this.options.rebuildPrograms) for (const command of this.bridgeBuildCommands()) console.log(`  (real build) ${commandText(command)}`);
            console.log(`  ${solanaRunning ? "(reuse)" : "(start)"} ${commandText(this.solanaCommand())}`);
            console.log(`  (verify) ${this.programs.length} executable program accounts including delegated-manager-set; solana program dump doge-bridge; SHA-256 equals local ELF`);
            const genProof = path.join(this.options.sp1Repo, "target/release/gen-proof");
            if (!firstExecutable([genProof])) console.log("  (build one-shot only) cargo build --release -p psy-bridge-sp1-script --bin gen-proof");
            console.log(`  (checked one-shot, not started) ${genProof}`);
        }
        if (c.has("initialize")) console.log("  (one-shot) doge-bridge-cli initialize-from-doge-data --airdrop --yes");
        if (c.has("users")) console.log("  (one-shot) doge-bridge-cli create-user x3 (missing user files only)");
        if (c.has("block-sender")) console.log(`  (start) node dist/index.js on 127.0.0.1:${BLOCK_SENDER_PORT}`);
        if (c.has("ibc-pipeline")) {
            console.log(`  (start) cargo run --release -p qed_dsol_ibc_node_common --example e2e_block_pipeline -- --electrs-url ${this.electrsUrl()} --network regtest ...`);
        }
        if (c.has("manager-service")) console.log(`  (start) ${this.localOpsCli()} --network localhost manager-service --listen 127.0.0.1:${MANAGER_SERVICE_PORT}`);
        if (c.has("noop-monitor")) console.log(`  (start) noop_shim_monitor ${SOLANA_RPC_URL} ${BRIDGE_STATE_PDA}`);
        console.log("");
        return { dogeRunning, solanaRunning, electrsRunning };
    }

    async buildMissing(status: { dogeRunning: boolean; solanaRunning: boolean; electrsRunning: boolean }): Promise<{ dogeDaemon: string | null; dogeCli: string | null; electrs: string | null }> {
        const c = this.options.components;
        let doge = this.findDogeBinaries();
        if (c.has("dogecoin") && !status.dogeRunning && (!doge.daemon || !doge.cli)) {
            if (!fs.existsSync(path.join(this.options.dogecoinRepo, "configure"))) {
                await this.run([path.join(this.options.dogecoinRepo, "autogen.sh")], "build-dogecoin-autogen", this.options.dogecoinRepo);
            }
            if (!fs.existsSync(path.join(this.options.dogecoinRepo, "Makefile"))) {
                await this.run([path.join(this.options.dogecoinRepo, "configure"), "--without-gui", "--disable-tests", "--disable-bench"], "build-dogecoin-configure", this.options.dogecoinRepo);
            }
            await this.run(["make", `-j${Math.max(1, os.availableParallelism())}`, "src/dogecoind", "src/dogecoin-cli"], "build-dogecoin", this.options.dogecoinRepo);
            doge = this.findDogeBinaries();
            if (!doge.daemon || !doge.cli) fail("Dogecoin build completed but dogecoind/dogecoin-cli were not found.");
        }

        let electrs = this.findElectrsBinary();
        if (c.has("electrs") && !status.electrsRunning && !electrs) {
            await this.run(["cargo", "build", "--release", "--bin", "electrs"], "build-electrs", this.options.electrsRepo);
            electrs = this.findElectrsBinary();
            if (!electrs) fail("electrs-doge build completed but target/release/electrs was not found.");
        }

        if ((c.has("manager-service") || c.has("deposit") || c.has("withdraw")) && !firstExecutable([this.localOpsCli()])) {
            await this.run(["cargo", "build", "--release", "--bin", "doge-solana-cli"], "build-doge-solana-cli", this.localOpsRoot());
            if (!firstExecutable([this.localOpsCli()])) fail(`doge-solana-cli build did not produce ${this.localOpsCli()}`);
        }

        if (c.has("solana") && (this.options.rebuildPrograms || this.programs.some((program) => !fs.existsSync(program.elf)))) {
            for (const [index, command] of this.bridgeBuildCommands().entries()) await this.run(command, `build-bridge-${index + 1}`, this.options.bridgeRepo);
            for (const program of this.programs) if (!fs.existsSync(program.elf)) fail(`Bridge build did not produce ${program.elf}`);
            const manifest = Object.fromEntries(this.programs.map((program) => [program.name, { id: program.id, elf: program.elf, sha256: fileSha256(program.elf) }]));
            fs.writeFileSync(path.join(this.runDir, "local-program-build.json"), `${JSON.stringify({ features: "solprogram,noopshim; no defaults; no mock-zkp", programs: manifest }, null, 2)}\n`);
        }

        if (c.has("solana")) {
            const genProof = path.join(this.options.sp1Repo, "target/release/gen-proof");
            if (!firstExecutable([genProof])) {
                await this.run(["cargo", "build", "--release", "-p", "psy-bridge-sp1-script", "--bin", "gen-proof"], "build-sp1-block-prover", this.options.sp1Repo);
            }
            if (!firstExecutable([genProof])) fail("SP1 block prover build completed but target/release/gen-proof was not found/executable.");
        }
        return { dogeDaemon: doge.daemon, dogeCli: doge.cli, electrs };
    }



    async startDogecoin(daemon: string, alreadyRunning: boolean): Promise<void> {
        ensureDirectory(DOGE_DATA_DIR);
        if (!alreadyRunning) {
            await this.spawn(this.dogeCommand(daemon), "dogecoind", this.options.dogecoinRepo, true);
            await waitFor("Dogecoin regtest RPC", 60_000, async () => await dogeInfo(this.options));
            await waitFor("Dogecoin P2P port", 10_000, async () => await portOpen(PORTS.dogeP2p));
        } else {
            console.log("[reuse:dogecoind] Compatible external/previous regtest service is already healthy; it is not owned by this run.");
        }
        const height = Number(await jsonRpc(DOGE_RPC_URL, "getblockcount", [], { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword }));
        if (height < 101) {
            const address = await jsonRpc(DOGE_RPC_URL, "getnewaddress", [], { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword });
            const blocks = 101 - height;
            console.log(`[bootstrap:dogecoin] Mining ${blocks} blocks to reach height 101.`);
            await jsonRpc(DOGE_RPC_URL, "generatetoaddress", [blocks, address], { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword });
        }
        const finalHeight = Number(await jsonRpc(DOGE_RPC_URL, "getblockcount", [], { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword }));
        if (finalHeight < 101) fail(`Dogecoin bootstrap failed: height is ${finalHeight}.`);
        console.log(`[ready:dogecoin] regtest height ${finalHeight}; RPC ${PORTS.dogeRpc}; P2P ${PORTS.dogeP2p}`);
    }

    async startElectrs(binary: string, alreadyRunning: boolean): Promise<void> {
        ensureDirectory(ELECTRS_DATA_DIR);
        if (!alreadyRunning) {
            await this.spawn(this.electrsCommand(binary), "electrs-doge", this.options.electrsRepo, true);
        } else {
            console.log("[reuse:electrs] Compatible electrs service is already responding; it is not owned by this run.");
        }
        await waitFor("electrs indexing to Dogecoin tip", 180_000, async () => {
            const indexed = await electrsHeight();
            if (indexed === null) return null;
            const dogeHeight = Number(await jsonRpc(DOGE_RPC_URL, "getblockcount", [], { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword }));
            return indexed === dogeHeight ? indexed : null;
        });
        const height = await electrsHeight();
        console.log(`[ready:electrs] indexed height ${height}; HTTP ${PORTS.electrsHttp}; Electrum ${PORTS.electrum}; metrics ${PORTS.electrsMetrics}`);
    }

    async prepareLocalSmokeFunding(): Promise<void> {
        const artifactPath = this.options.localSmokeFundingArtifact;
        if (!artifactPath) return;
        assertWritableNewPath(artifactPath);
        const rpcAuth = { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword };
        const addressValue = await jsonRpc(DOGE_RPC_URL, "getnewaddress", [], rpcAuth);
        if (typeof addressValue !== "string" || addressValue.length === 0) fail("getnewaddress did not return a funding address.");
        const address = addressValue;
        fundingP2pkhScriptHash(address);
        console.log(`[funding] Mining exactly ${LOCAL_SMOKE_FUNDING_BLOCKS} blocks to fresh address ${address}.`);
        const mined = await jsonRpc(DOGE_RPC_URL, "generatetoaddress", [LOCAL_SMOKE_FUNDING_BLOCKS, address], rpcAuth);
        if (!Array.isArray(mined) || mined.length !== LOCAL_SMOKE_FUNDING_BLOCKS) {
            fail(`generatetoaddress returned ${Array.isArray(mined) ? mined.length : "non-array"} block hashes; expected ${LOCAL_SMOKE_FUNDING_BLOCKS}.`);
        }
        const indexedHeight = await waitFor("Electrs indexing local smoke funding blocks", 180_000, async () => {
            const indexed = await electrsHeight();
            if (indexed === null) return null;
            const dogeHeight = Number(await jsonRpc(DOGE_RPC_URL, "getblockcount", [], rpcAuth));
            return Number.isInteger(dogeHeight) && indexed === dogeHeight ? indexed : null;
        });
        const candidates = (await fundingUtxos(address))
            .filter((utxo) => {
                if (!utxo.status.confirmed || utxo.status.block_height === undefined || utxo.value < LOCAL_SMOKE_MIN_VALUE_SATS) return false;
                return indexedHeight - utxo.status.block_height + 1 >= LOCAL_SMOKE_MIN_CONFIRMATIONS;
            })
            .sort((left, right) =>
                (left.status.block_height! - right.status.block_height!) || left.txid.localeCompare(right.txid) || left.vout - right.vout
            );
        const selected = candidates[0];
        if (!selected || selected.status.block_height === undefined) {
            fail(`No funding UTXO has at least ${LOCAL_SMOKE_MIN_CONFIRMATIONS} confirmations and ${LOCAL_SMOKE_MIN_VALUE_SATS} satoshis.`);
        }
        const confirmations = indexedHeight - selected.status.block_height + 1;
        const wifValue = await jsonRpc(DOGE_RPC_URL, "dumpprivkey", [address], rpcAuth);
        if (typeof wifValue !== "string" || wifValue.length === 0) fail("dumpprivkey did not return a WIF.");
        writeJsonAtomic(artifactPath, {
            schema: LOCAL_SMOKE_FUNDING_SCHEMA,
            createdAt: new Date().toISOString(),
            network: "regtest",
            address,
            wif: wifValue,
            txid: selected.txid,
            vout: selected.vout,
            value: selected.value,
            blockHeight: selected.status.block_height,
            confirmations,
            minedBlocks: LOCAL_SMOKE_FUNDING_BLOCKS,
            minimumConfirmations: LOCAL_SMOKE_MIN_CONFIRMATIONS,
            minimumValue: LOCAL_SMOKE_MIN_VALUE_SATS,
            dogecoinTipHeight: indexedHeight,
            electrsTipHeight: indexedHeight,
        });
        const publishedMode = fs.statSync(artifactPath).mode & 0o777;
        if (publishedMode !== 0o600) fail(`Funding artifact ${artifactPath} has mode ${publishedMode.toString(8)}, expected 600.`);
        console.log(`[funding] Published mature UTXO ${selected.txid}:${selected.vout} (${selected.value} sats, ${confirmations} confirmations) to mode-600 ${artifactPath}.`);
    }

    async verifyProgramAccounts(dumpBridge: boolean): Promise<void> {
        for (const program of this.programs) {
            const value = await jsonRpc(SOLANA_RPC_URL, "getAccountInfo", [program.id, { encoding: "base64", commitment: "confirmed" }]);
            if (!value?.value?.executable) fail(`Solana program account ${program.name} (${program.id}) is absent or not executable.`);
        }
        if (!dumpBridge) return;
        const bridge = this.programs[0];
        const dumpPath = path.join(this.runDir, "deployed-doge-bridge.so");
        await this.run(["solana", "program", "dump", bridge.id!, dumpPath, "--url", SOLANA_RPC_URL], "dump-doge-bridge", this.options.bridgeRepo);
        const localHash = fileSha256(bridge.elf);
        const deployedHash = fileSha256(dumpPath);
        fs.writeFileSync(path.join(this.runDir, "deployed-program-hashes.json"), `${JSON.stringify({
            dogeBridgeProgramId: bridge.id,
            localElf: bridge.elf,
            dumpedElf: dumpPath,
            localSha256: localHash,
            deployedSha256: deployedHash,
            allLocalPrograms: Object.fromEntries(this.programs.map((program) => [program.name, { id: program.id, sha256: fileSha256(program.elf) }])),
        }, null, 2)}\n`);
        if (localHash !== deployedHash) fail(`Deployed doge-bridge ELF hash ${deployedHash} does not match local real/noop artifact ${localHash}. Teardown the existing validator or use matching artifacts.`);
        console.log(`[verify:solana] ${this.programs.length} executable programs including delegated-manager-set; doge-bridge SHA-256 ${localHash}`);
        console.log(`[artifact:solana] ${dumpPath}`);
    }

    async startSolana(alreadyRunning: boolean): Promise<void> {
        ensureDirectory(SOLANA_LEDGER_DIR);
        if (!alreadyRunning) {
            await this.spawn(this.solanaCommand(), "solana-validator", this.options.bridgeRepo, true);
            await waitFor("Solana RPC health", 90_000, async () => await solanaHealthy());
            await waitFor("Solana websocket", 15_000, async () => await portOpen(PORTS.solanaWs));
            await waitFor("Solana faucet", 15_000, async () => await portOpen(PORTS.solanaFaucet));
        } else {
            console.log("[reuse:solana] Compatible validator is already healthy; it is not owned by this run.");
        }
        await this.verifyProgramAccounts(true);
        console.log(`[ready:solana] RPC ${PORTS.solanaRpc}; WS ${PORTS.solanaWs}; faucet ${PORTS.solanaFaucet}`);
    }

    async ensureLocalOpsCli(): Promise<string> {
        const cli = this.localOpsCli();
        if (!firstExecutable([cli])) {
            if (this.options.noBuild) fail(`Missing doge-solana-cli and --no-build was set: ${cli}`);
            await this.run(["cargo", "build", "--release", "--bin", "doge-solana-cli"], "build-doge-solana-cli", this.localOpsRoot());
        }
        if (!firstExecutable([cli])) fail(`doge-solana-cli build did not produce ${cli}`);
        return cli;
    }

    async ensureBridgeCli(): Promise<string> {
        const cli = path.join(this.options.bridgeRepo, "target/release/doge-bridge-cli");
        if (!firstExecutable([cli])) {
            if (this.options.noBuild) fail(`Missing bridge CLI and --no-build was set: ${cli}`);
            await this.run(["cargo", "build", "--release", "-p", "doge-bridge-cli", "--bin", "doge-bridge-cli"], "build-bridge-cli", this.options.bridgeRepo);
        }
        if (!firstExecutable([cli])) fail(`Bridge CLI build did not produce ${cli}`);
        return cli;
    }

    async accountExists(address: string): Promise<boolean> {
        try {
            const value = await jsonRpc(SOLANA_RPC_URL, "getAccountInfo", [address, { encoding: "base64", commitment: "confirmed" }]);
            return Boolean(value?.value);
        } catch {
            return false;
        }
    }

    localManagerSetPdas(): { index: string; set: string } {
        const program = new PublicKey(DELEGATED_MANAGER_SET_ID);
        const chain = Buffer.alloc(2);
        chain.writeUInt16BE(DOGECOIN_WORMHOLE_CHAIN_ID);
        const index = Buffer.alloc(4);
        index.writeUInt32BE(LOCAL_MANAGER_SET_INDEX);
        return {
            index: PublicKey.findProgramAddressSync([Buffer.from("manager_set_index"), chain], program)[0].toBase58(),
            set: PublicKey.findProgramAddressSync([Buffer.from("manager_set"), chain, index], program)[0].toBase58(),
        };
    }

    async managerSetAccountMatches(address: string): Promise<boolean> {
        try {
            const value = await jsonRpc(SOLANA_RPC_URL, "getAccountInfo", [address, { encoding: "base64", commitment: "confirmed" }]);
            if (value?.value?.owner !== DELEGATED_MANAGER_SET_ID) return false;
            const encoded = value?.value?.data?.[0];
            if (typeof encoded !== "string") return false;
            const data = Buffer.from(encoded, "base64");
            if (data.length !== 8 + 2 + 4 + 4 + LOCAL_MANAGER_SET_BYTES.length) return false;
            if (data.readUInt16LE(8) !== DOGECOIN_WORMHOLE_CHAIN_ID || data.readUInt32LE(10) !== LOCAL_MANAGER_SET_INDEX) return false;
            const length = data.readUInt32LE(14);
            return length === LOCAL_MANAGER_SET_BYTES.length && data.subarray(18).equals(LOCAL_MANAGER_SET_BYTES);
        } catch {
            return false;
        }
    }

    async initializeLocalManagerSet(cli: string, payer: string, payerPubkey: string): Promise<void> {
        const pdas = this.localManagerSetPdas();
        if (await this.managerSetAccountMatches(pdas.set)) {
            console.log(`[reuse:manager-set] ${pdas.set} already contains the deterministic local 5-of-7 manager set.`);
            return;
        }
        const config = path.join(this.runDir, "local-manager-set.yaml");
        fs.writeFileSync(config, `custodian_wallet_public_keys:\n${LOCAL_MANAGER_SET_PUBKEYS.map((key) => `  - "${key}"`).join("\n")}\n`, { mode: 0o600 });
        await waitFor("initialized payer funding", 30_000, async () => {
            const balance = await jsonRpc(SOLANA_RPC_URL, "getBalance", [payerPubkey, { commitment: "confirmed" }]);
            const lamports = Number(balance?.value);
            return Number.isSafeInteger(lamports) && lamports > 0 ? lamports : null;
        });
        await this.run([
            cli, "--rpc-url", SOLANA_RPC_URL,
            "-k", payer,
            "init-delegated-manager",
            "--config", config,
            "--chain-id", String(DOGECOIN_WORMHOLE_CHAIN_ID),
            "--set-index", String(LOCAL_MANAGER_SET_INDEX),
        ], "initialize-local-manager-set", this.options.bridgeRepo);
        if (!(await this.managerSetAccountMatches(pdas.set)) || !(await this.accountExists(pdas.index))) {
            fail(`Delegated manager set initialization did not publish the expected 5-of-7 accounts (${pdas.index}, ${pdas.set}).`);
        }
        console.log(`[ready:manager-set] index=${pdas.index} set=${pdas.set} threshold=5/7`);
    }

    async generateRegtestBridgeConfig(): Promise<{ configPath: string; height: number; hash: string }> {
        const generator = this.localOpsExample("generate_regtest_init");
        if (!firstExecutable([generator])) {
            if (this.options.noBuild) fail(`Missing regtest init generator and --no-build was set: ${generator}`);
            await this.run(["cargo", "build", "--release", "--example", "generate_regtest_init"], "build-regtest-init-generator", this.localOpsRoot());
        }
        const dogeHeight = Number(await jsonRpc(DOGE_RPC_URL, "getblockcount", [], { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword }));
        const electrsTipText = await fetch(`${this.electrsUrl()}/blocks/tip/height`).then(async (response) => {
            if (!response.ok) fail(`Electrs tip query returned ${response.status}: ${await response.text()}`);
            return await response.text();
        });
        const electrsHeight = Number(electrsTipText.trim());
        if (!Number.isInteger(dogeHeight) || dogeHeight < 32 || electrsHeight !== dogeHeight) {
            fail(`Cannot generate bridge checkpoint: Dogecoin height=${dogeHeight}, Electrs height=${electrsHeight}`);
        }
        const checkpointHeight = dogeHeight - 1;
        const checkpointHash = String(await jsonRpc(DOGE_RPC_URL, "getblockhash", [checkpointHeight], { user: this.options.dogeRpcUser, password: this.options.dogeRpcPassword }));
        const configPath = path.join(this.runDir, "doge-regtest-init.json");
        const templatePath = path.join(this.options.bridgeRepo, "bridge-config", "doge_config.json");
        const custodyScriptConfig = Buffer.from(bs58.decode(BRIDGE_STATE_PDA)).toString("hex");
        await this.run([
            generator,
            "--template", templatePath,
            "--output", configPath,
            "--electrs-url", this.electrsUrl(),
            "--checkpoint-height", String(checkpointHeight),
            "--required-confirmations", "1",
            "--custody-script-config", custodyScriptConfig,
            "--expected-block-hash", checkpointHash,
        ], "generate-regtest-init", this.localOpsRoot());
        this.bridgeCheckpoint = { configPath, height: checkpointHeight, hash: checkpointHash };
        return this.bridgeCheckpoint;
    }

    async initializeBridge(createUsers: boolean): Promise<void> {
        const cli = await this.ensureBridgeCli();
        const configDir = path.join(this.options.bridgeRepo, "bridge-config");
        const dogeConfig = path.join(configDir, "doge_config.json");
        const keysDir = path.join(configDir, "keys");
        const usersDir = path.join(configDir, "users");
        const output = path.join(configDir, "bridge-output.json");
        if (!fs.existsSync(dogeConfig)) fail(`Missing bridge initialization config: ${dogeConfig}`);
        ensureDirectory(keysDir);
        ensureDirectory(usersDir);
        if (!this.bridgeCheckpoint && this.options.dogecoind) {
            await this.generateRegtestBridgeConfig();
        }
        const activeDogeConfig = this.bridgeCheckpoint?.configPath ?? dogeConfig;
        if (!(await this.accountExists(BRIDGE_STATE_PDA))) {
            await this.run([
                cli, "--rpc-url", SOLANA_RPC_URL,
                "initialize-from-doge-data",
                "--config", activeDogeConfig,
                "--keys-dir", keysDir,
                "--output", output,
                "--airdrop",
                "--yes",
            ], "initialize-bridge", this.options.bridgeRepo);
        } else {
            console.log(`[reuse:bridge] Bridge state ${BRIDGE_STATE_PDA} already exists; initialization skipped.`);
        }
        if (!fs.existsSync(output)) fail(`Bridge is initialized but ${output} is missing; cannot safely infer the mint/users. Restore matching bridge output or reset the validator.`);
        const bridgeOutput = JSON.parse(fs.readFileSync(output, "utf8")) as { doge_mint?: string; bridge_state_pda?: string; payer_pubkey?: string };
        if (bridgeOutput.bridge_state_pda !== BRIDGE_STATE_PDA || !bridgeOutput.doge_mint || !bridgeOutput.payer_pubkey) fail(`Invalid or mismatched bridge output: ${output}`);
        const payer = path.join(keysDir, "payer.json");
        if (!fs.existsSync(payer)) fail(`Missing initialized payer key: ${payer}`);
        await this.initializeLocalManagerSet(cli, payer, bridgeOutput.payer_pubkey);
        if (this.bridgeCheckpoint) {
            const stateAccount = await jsonRpc(SOLANA_RPC_URL, "getAccountInfo", [BRIDGE_STATE_PDA, { encoding: "base64", commitment: "confirmed" }]);
            const encoded = stateAccount?.value?.data?.[0];
            if (typeof encoded !== "string") fail("Bridge initialization completed without readable bridge state data");
            const state = Buffer.from(encoded, "base64");
            const onChainHeight = state.readUInt32LE(68);
            const expectedHashInternal = Buffer.from(this.bridgeCheckpoint.hash, "hex").reverse();
            if (onChainHeight !== this.bridgeCheckpoint.height || !state.subarray(0, 32).equals(expectedHashInternal)) {
                fail(`Initialized bridge checkpoint mismatch: on-chain height=${onChainHeight}, expected=${this.bridgeCheckpoint.height}`);
            }
        }
        if (createUsers) {
            if (!fs.existsSync(payer)) fail(`Missing initialized payer key: ${payer}`);
            for (const name of ["user1", "user2", "user3"]) {
                const userOutput = path.join(usersDir, `${name}.json`);
                const userExists = fs.existsSync(userOutput);
                if (userExists) {
                    const user = JSON.parse(fs.readFileSync(userOutput, "utf8")) as { doge_ata?: string; private_key?: number[] };
                    if (user.doge_ata && await this.accountExists(user.doge_ata)) {
                        console.log(`[reuse:user] ${userOutput}`);
                        continue;
                    }
                    if (!Array.isArray(user.private_key) || user.private_key.length !== 64) {
                        fail(`Cannot repair ${userOutput}: expected a 64-byte private_key array`);
                    }
                    const userKeypair = path.join(this.runDir, `${name}-keypair.json`);
                    fs.writeFileSync(userKeypair, JSON.stringify(user.private_key), { mode: 0o600 });
                    await this.run([
                        cli, "--rpc-url", SOLANA_RPC_URL,
                        "-k", payer,
                        "create-user",
                        "--doge-mint", bridgeOutput.doge_mint,
                        "--output", userOutput,
                        "--user-keypair", userKeypair,
                    ], `repair-${name}`, this.options.bridgeRepo);
                    console.log(`[repair:user] Recreated ATA while preserving ${name} identity`);
                    continue;
                }
                await this.run([
                    cli, "--rpc-url", SOLANA_RPC_URL,
                    "-k", payer,
                    "create-user",
                    "--doge-mint", bridgeOutput.doge_mint,
                    "--output", userOutput,
                ], `create-${name}`, this.options.bridgeRepo);
            }
        }
        console.log(`[ready:bridge] initialized state ${BRIDGE_STATE_PDA}${createUsers ? " with three user records" : ""}`);
    }

    async startNoopMonitor(): Promise<void> {
        const output = path.join(this.options.bridgeRepo, "bridge-config/bridge-output.json");
        if (!fs.existsSync(output) || !(await this.accountExists(BRIDGE_STATE_PDA))) {
            fail("--noop-monitor requires an initialized bridge and matching bridge-config/bridge-output.json. Use --initialize first.");
        }
        const binary = path.join(this.options.bridgeRepo, "target/debug/examples/noop_shim_monitor");
        if (!firstExecutable([binary])) {
            if (this.options.noBuild) fail(`Missing noop monitor and --no-build was set: ${binary}`);
            await this.run(["cargo", "build", "-p", "doge-bridge-client", "--example", "noop_shim_monitor"], "build-noop-monitor", this.options.bridgeRepo);
        }
        await this.spawn([binary, SOLANA_RPC_URL, BRIDGE_STATE_PDA], "noop-shim-monitor", this.options.bridgeRepo, true);
        await sleep(500);
        console.log(`[ready:noop-monitor] polling ${SOLANA_RPC_URL}; no listening port`);
    }


    localOpsRoot(): string {
        return path.join(CLI_REPO, "doge");
    }

    /** Unified CLI binary path (Cargo [[bin]] doge-solana-cli). */
    localOpsCli(): string {
        return path.join(this.localOpsRoot(), "target", "release", "doge-solana-cli");
    }

    /** Example/helper binaries that are not subcommands of doge-solana-cli. */
    localOpsExample(name: string): string {
        return path.join(this.localOpsRoot(), "target", "release", "examples", name);
    }

    electrsUrl(): string {
        return ELECTRS_HTTP_URL;
    }

    bridgeKeys(): { operator: string; payer: string; store: string } {
        const keysDir = path.join(this.options.bridgeRepo, "bridge-config", "keys");
        return {
            operator: path.join(keysDir, "operator.json"),
            payer: path.join(keysDir, "payer.json"),
            store: path.join(keysDir, "operator-store.sqlite"),
        };
    }

    async ensureLocalPipelineFunding(): Promise<void> {
        for (const [role, keypair] of Object.entries(this.bridgeKeys()).filter(([name]) => name !== "store")) {
            const pubkey = this.keypairPubkey(keypair);
            const current = await jsonRpc(SOLANA_RPC_URL, "getBalance", [pubkey, { commitment: "confirmed" }]);
            const lamports = Number(current?.value);
            if (!Number.isSafeInteger(lamports)) fail(`Could not read ${role} balance for local pipeline funding.`);
            if (lamports >= 1_000_000_000) continue;
            await this.run(
                ["solana", "airdrop", "2", pubkey, "--url", SOLANA_RPC_URL],
                `airdrop-${role}`,
                this.options.bridgeRepo,
            );
            await waitFor(`${role} airdrop confirmation`, 30_000, async () => {
                const balance = await jsonRpc(SOLANA_RPC_URL, "getBalance", [pubkey, { commitment: "confirmed" }]);
                const funded = Number(balance?.value);
                return Number.isSafeInteger(funded) && funded >= 1_000_000_000 ? funded : null;
            });
        }
    }
    async blockPipelineConfig(): Promise<{
        custodyScriptConfig: string;
        recipientAtas: string;
        startHeight: number;
        configParams: string;
        initialHeader: string;
        operatorKeypair: string;
        payerKeypair: string;
        dogeMint: string;
    }> {
        const configPath = this.bridgeCheckpoint?.configPath ?? path.join(this.options.bridgeRepo, "bridge-config", "doge_config.json");
        const outputPath = path.join(this.options.bridgeRepo, "bridge-config", "bridge-output.json");
        const userPath = path.join(this.options.bridgeRepo, "bridge-config", "users", "user1.json");
        const config = JSON.parse(fs.readFileSync(configPath, "utf8")) as {
            config_params?: Record<string, number>;
        };
        const output = JSON.parse(fs.readFileSync(outputPath, "utf8")) as {
            doge_mint?: string;
            operator_pubkey?: string;
            operator_pubkey_hex?: string;
            bridge_state_pda_hex?: string;
        };
        const user = JSON.parse(fs.readFileSync(userPath, "utf8")) as {
            doge_ata_hex?: string;
            doge_ata?: string;
        };
        if (!output.doge_mint || !user.doge_ata_hex || !user.doge_ata) {
            fail("IBC pipeline requires initialized bridge output and user1 pubkey/token account");
        }
        const account = await jsonRpc(SOLANA_RPC_URL, "getAccountInfo", [BRIDGE_STATE_PDA, { encoding: "base64", commitment: "confirmed" }]);
        const encoded = account?.value?.data?.[0];
        if (typeof encoded !== "string") fail("IBC pipeline cannot read initialized bridge state");
        const state = Buffer.from(encoded, "base64");
        if (state.length < 320) fail(`Bridge state is too short for a 320-byte header: ${state.length}`);
        const params = config.config_params;
        if (!params || !output.bridge_state_pda_hex || output.bridge_state_pda_hex.length !== 64) fail(`Invalid bridge config/output ${configPath}`);
        const u64le = (value: number): Buffer => {
            const bytes = Buffer.alloc(8);
            bytes.writeBigUInt64LE(BigInt(value));
            return bytes;
        };
        const configParams = Buffer.concat([
            u64le(params.deposit_fee_rate_numerator),
            u64le(params.deposit_fee_rate_denominator),
            u64le(params.withdrawal_fee_rate_numerator),
            u64le(params.withdrawal_fee_rate_denominator),
            u64le(params.deposit_flat_fee_sats),
            u64le(params.withdrawal_flat_fee_sats),
        ]).toString("hex");
        return {
            custodyScriptConfig: output.bridge_state_pda_hex,
            recipientAtas: user.doge_ata_hex,
            startHeight: this.bridgeCheckpoint?.height ?? state.readUInt32LE(68),
            configParams,
            initialHeader: state.subarray(0, 320).toString("hex"),
            operatorKeypair: this.bridgeKeys().operator,
            payerKeypair: this.bridgeKeys().payer,
            dogeMint: output.doge_mint,
        };
    }


    async prepareBlockPipelineConfig(): Promise<string[]> {
        const config = await this.blockPipelineConfig();
        return [
            "--custody-script-config", config.custodyScriptConfig,
            "--recipient-atas", config.recipientAtas,
            "--start-height", String(config.startHeight),
            "--deposit-evidence-path", "/tmp/local-smoke-deposit-evidence.json",
            "--config-params", config.configParams,
            "--initial-header", config.initialHeader,
            "--solana-rpc-url", SOLANA_RPC_URL,
            "--operator-keypair", config.operatorKeypair,
            "--payer-keypair", config.payerKeypair,
            "--doge-mint", config.dogeMint,
        ];
    }

    async startIbcCheckpointRedis(): Promise<void> {
        const name = `psy-doge-local-smoke-checkpoint-${this.runId}`.toLowerCase().replace(/[^a-z0-9_.-]/g, "-");
        const result = Bun.spawnSync([
            "docker", "run", "-d", "--rm",
            "--name", name,
            "--label", `psy.doge.launcher.run=${this.runId}`,
            "--publish", `127.0.0.1:${PORTS.checkpointRedis}:6379`,
            "redis:7-alpine",
        ], { stdout: "pipe", stderr: "pipe" });
        if (result.exitCode !== 0) fail(`Failed to start local smoke checkpoint Redis container: ${result.stderr.toString()}`);
        const id = result.stdout.toString().trim();
        this.state.containers.push({ role: "ibc-checkpoint-redis", id, name });
        this.persist();
        await waitFor("IBC checkpoint Redis TCP", 30_000, async () => await portOpen(PORTS.checkpointRedis));
        console.log(`[ready:ibc-checkpoint] Redis ${id.slice(0, 12)} on 127.0.0.1:${PORTS.checkpointRedis}`);
    }

    async startBlockSender(): Promise<void> {
        const senderDir = path.join(this.options.projectsDir, "solana-doge-bridge-block-sender", "apps", "sol-send-server");
        if (!fs.existsSync(path.join(senderDir, "dist", "index.js"))) {
            fail(`Block sender build is missing: ${path.join(senderDir, "dist/index.js")}`);
        }
        const { payer: payerKeypair, operator: operatorKeypair } = this.bridgeKeys();
        const secretHex = (role: string, keypair: string): string => {
            if (!fs.existsSync(keypair)) fail(`Block sender ${role} keypair is missing: ${keypair}. Initialize the bridge first.`);
            const bytes = JSON.parse(fs.readFileSync(keypair, "utf8")) as unknown;
            if (!Array.isArray(bytes) || bytes.length < 32 || bytes.slice(0, 32).some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
                fail(`Block sender ${role} keypair is invalid: ${keypair}`);
            }
            return Buffer.from(bytes.slice(0, 32) as number[]).toString("hex");
        };
        const payerSecretHex = secretHex("payer", payerKeypair);
        const operatorSecretHex = secretHex("operator", operatorKeypair);
        await this.spawn(
            ["node", "dist/index.js"],
            "block-sender",
            senderDir,
            true,
            {
                API_TOKEN: BLOCK_SENDER_API_TOKEN,
                SOLANA_RPC_URL,
                SOL_RPC_URL: SOLANA_RPC_URL,
                SOL_WEBSOCKET_URL: `ws://127.0.0.1:${PORTS.solanaWs}`,
                SOL_PAYER_SECRET_KEY: payerSecretHex,
                SOL_OPERATOR_SECRET_KEY: operatorSecretHex,
                LISTEN_PORT: String(BLOCK_SENDER_PORT),
                NEEDS_AIRDROP: "false",
            },
        );
        await waitFor("block-sender TCP", 15_000, async () => await portOpen(BLOCK_SENDER_PORT));
        console.log(`[ready:block-sender] port ${BLOCK_SENDER_PORT}`);
    }

    async startIbcPipeline(): Promise<void> {
        const ibcDir = path.join(this.options.projectsDir, "solana-doge-ibc");
        const electrsUrl = this.electrsUrl();
        const bridgeArgs = await this.prepareBlockPipelineConfig();
        const network = "regtest";
        const blockElfPath = process.env.SP1_BLOCK_ELF_PATH
            || path.join(this.options.sp1Repo, "target/elf-compilation/riscv64im-succinct-zkvm-elf/release/block-transition");
        const expectedVk = process.env.SP1_BLOCK_VK_HASH
            || "002ed3c169b6415db45e569dd01675bfb2ba89c59c7d26582f3a22d2ec313ee8";
        const command = [
            "cargo", "run", "--release", "-p", "qed_dsol_ibc_node_common",
            "--example", "e2e_block_pipeline", "--",
            "--electrs-url", electrsUrl,
            "--redis-url", `redis://127.0.0.1:${PORTS.checkpointRedis}`,
            "--sender-url", `http://127.0.0.1:${BLOCK_SENDER_PORT}`,
            "--gen-proof-path", path.join(this.options.sp1Repo, "target/release/gen-proof"),
            "--required-confirmations", "1",
            "--network", network,
            ...bridgeArgs,
        ];
        if (fs.existsSync(blockElfPath)) {
            command.push("--block-elf-path", blockElfPath);
        }
        command.push("--expected-vk-hash", expectedVk);
        await this.spawn(command, "ibc-pipeline", ibcDir, true, {
            DOGE_SAVE_PROVER_ARGS: "1",
            DOGE_BLOCK_SENDER_TOKEN: BLOCK_SENDER_API_TOKEN,
        });
        console.log(`[ready:ibc-pipeline] polling ${electrsUrl} network=${network}`);
    }

    async startManagerService(): Promise<void> {
        const bin = await this.ensureLocalOpsCli();
        await this.spawn([bin, "--network", "localhost", "manager-service", "--listen", `127.0.0.1:${MANAGER_SERVICE_PORT}`], "manager-service", this.localOpsRoot(), true);
        await waitFor("manager-service TCP", 10_000, async () => await portOpen(MANAGER_SERVICE_PORT));
        console.log(`[ready:manager-service] port ${MANAGER_SERVICE_PORT}`);
    }

    async runDeposit(options: { fundingWifFile: string; fundingTxid: string; fundingVout: number; fundingAmount: number; recipientTokenAccount: string }): Promise<void> {
        const keys = this.bridgeKeys();
        const cli = await this.ensureLocalOpsCli();
        await this.run([
            cli,
            "--network", "localhost",
            "deposit",
            "--funding-wif-file", options.fundingWifFile,
            "--funding-txid", options.fundingTxid,
            "--funding-vout", String(options.fundingVout),
            "--funding-amount", String(options.fundingAmount),
            "--recipient-token-account", options.recipientTokenAccount,
            "--solana-rpc-url", SOLANA_RPC_URL,
            "--operator-keypair", keys.operator,
            "--payer-keypair", keys.payer,
            "--electrs-url", this.electrsUrl(),
            "--operator-store", keys.store,
        ], "deposit", this.localOpsRoot());
    }

    async runWithdrawal(options: { requestIndex: number }): Promise<void> {
        const keys = this.bridgeKeys();
        const cli = await this.ensureLocalOpsCli();
        await this.run([
            cli,
            "--network", "localhost",
            "withdraw",
            "--request-index", String(options.requestIndex),
            "--operator-keypair", keys.operator,
            "--payer-keypair", keys.payer,
            "--operator-store", keys.store,
            "--manager-service-url", `http://127.0.0.1:${MANAGER_SERVICE_PORT}`,
            "--electrs-url", this.electrsUrl(),
            "--wormhole-core-program", LOCAL_NOOP_SHIM_ID,
            "--wormhole-shim-program", LOCAL_NOOP_SHIM_ID,
            "--manager-set-index", "0",
            "--manager-signing-enabled",
            "--broadcast-enabled",
            "--solana-rpc-url", SOLANA_RPC_URL,
        ], "withdraw", this.localOpsRoot());
    }

    async start(): Promise<void> {
        if (loadActiveState()) fail(`Launcher state already exists at ${ACTIVE_STATE_PATH}. Run --teardown first; no unrecorded processes will be killed.`);
        const status = await this.preflight();
        if (this.options.dryRun) {
            console.log("[preflight] PASS — paths, tools/build prerequisites, artifacts/build plans, ports, and commands validated; no services spawned.");
            return;
        }
        ensureDirectory(this.runDir);
        this.persist();
        const binaries = await this.buildMissing(status);
        const c = this.options.components;
        if (c.has("dogecoin")) await this.startDogecoin(binaries.dogeDaemon!, status.dogeRunning);
        if (c.has("electrs")) await this.startElectrs(binaries.electrs!, status.electrsRunning);
        if (this.options.localSmokeFundingArtifact) await this.prepareLocalSmokeFunding();
        if (c.has("solana")) await this.startSolana(status.solanaRunning);
        if (c.has("initialize")) await this.initializeBridge(c.has("users"));
        if (c.has("ibc-pipeline") || c.has("block-sender")) await this.ensureLocalPipelineFunding();
        if (c.has("noop-monitor")) await this.startNoopMonitor();
        if (c.has("ibc-pipeline")) await this.startIbcCheckpointRedis();
        if (c.has("block-sender")) await this.startBlockSender();
        if (c.has("ibc-pipeline")) await this.startIbcPipeline();
        if (c.has("manager-service")) await this.startManagerService();

        const owned = this.state.processes.length + this.state.containers.length;
        console.log(`[ready] Profile ${this.options.profile} is operational. Run directory: ${this.runDir}`);
        console.log("[limitations] SP1 tools are one-shot and were not run. Current proofs do not establish arbitrary-history consensus/finality, and noop does not release Guardian-controlled DOGE UTXOs.");
        if (owned === 0) {
            removeActiveState();
            console.log("[ready] Every requested service was reused, so this launcher owns nothing and will exit without tearing anything down.");
            return;
        }
        console.log("Press Ctrl+C to stop only launcher-owned processes/container(s).");
        await new Promise<void>(() => {});
    }
}

async function teardown(purge: boolean): Promise<void> {
    const state = loadActiveState();
    if (!state) {
        console.log(`[teardown] No recorded active run at ${ACTIVE_STATE_PATH}; no processes or containers were touched.`);
        if (purge) {
            fs.rmSync(STATE_ROOT, { recursive: true, force: true });
            console.log(`[purge] Removed ${STATE_ROOT}`);
        }
        return;
    }
    const dummyOptions: Options = {
        profile: "local",
        dryRun: false,
        noBuild: true,
        rebuildPrograms: false,
        teardown: true,
        purge,
        components: new Set(),
        projectsDir: DEFAULT_PROJECTS_DIR,
        bridgeRepo: path.join(DEFAULT_PROJECTS_DIR, "psy-doge-solana-bridge"),
        dogecoinRepo: path.join(DEFAULT_PROJECTS_DIR, "dogecoin"),
        electrsRepo: path.join(DEFAULT_PROJECTS_DIR, "electrs-doge"),
        sp1Repo: path.join(DEFAULT_PROJECTS_DIR, "psy-bridge-sp1"),
        dogeRpcUser: "doge",
        dogeRpcPassword: "doge",
        dogecoind: true,
        deposit: false,
        withdraw: false,
    };
    const launcher = new Launcher(dummyOptions);
    launcher.state.runId = state.runId;
    launcher.state.runDir = state.runDir;
    launcher.state.processes = state.processes;
    launcher.state.containers = state.containers;
    await launcher.cleanup(purge);
    console.log("[teardown] Complete; only recorded ownership was targeted.");
}

async function runResolved(options: Options): Promise<void> {
    if (options.teardown) {
        await teardown(options.purge);
        return;
    }
    if (options.deploy) {
        await new Launcher(options).deployPublic();
        return;
    }
    const launcher = new Launcher(options);
    let signalHandled = false;
    const onSignal = (signal: string) => {
        if (signalHandled) return;
        signalHandled = true;
        console.log(`\n[signal] ${signal}`);
        void launcher.cleanup(false).finally(() => process.exit(0));
    };
    process.on("SIGINT", () => onSignal("SIGINT"));
    process.on("SIGTERM", () => onSignal("SIGTERM"));
    try {
        if (options.deposit) {
            await launcher.runDeposit({
                fundingWifFile: options.fundingWifFile!,
                fundingTxid: options.fundingTxid!,
                fundingVout: options.fundingVout!,
                fundingAmount: options.fundingAmount!,
                recipientTokenAccount: options.recipientTokenAccount!,
            });
            return;
        }
        if (options.withdraw) {
            await launcher.runWithdrawal({ requestIndex: options.requestIndex! });
            return;
        }
        await launcher.start();
    } catch (error) {
        if (loadActiveState()?.runId === launcher.runId) await launcher.cleanup(false);
        throw error;
    }
}

export async function runLocalLauncher(args: string[] = Bun.argv.slice(2)): Promise<void> {
    const options = resolveLocalOptions(args);
    if (options) await runResolved(options);
}

export async function runDevnetDeployment(args: string[] = Bun.argv.slice(2)): Promise<void> {
    const options = resolveDevnetOptions(args);
    if (options) await runResolved(options);
}
