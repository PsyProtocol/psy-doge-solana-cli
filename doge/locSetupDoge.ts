#!/usr/bin/env bun

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { connect } from "node:net";
import { parseArgs } from "node:util";

type Profile = "real-noop" | "initialized-noop" | "wormhole" | "legacy-ibc";
type Component = "dogecoin" | "electrs" | "solana" | "initialize" | "users" | "noop-monitor" | "legacy-ibc";
type DeploymentCluster = "local" | "devnet" | "testnet" | "custom";
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
    initialize: boolean;
    configPath: string;
    keysDir: string;
    outputPath: string;
    manifestPath: string;
    commitment: Commitment;
    yes: boolean;
    airdropSol?: number;
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
    wormhole?: { repo: string; commit: string; context: string; namespace: string };
};

type Program = { name: string; keypair: string; elf: string; id?: string };

type Options = {
    profile: Profile;
    dryRun: boolean;
    noBuild: boolean;
    rebuildPrograms: boolean;
    deploy?: DeploymentOptions;
    deploymentSmokeTest: boolean;
    teardown: boolean;
    purge: boolean;
    components: Set<Component>;
    projectsDir: string;
    bridgeRepo: string;
    dogecoinRepo: string;
    electrsRepo: string;
    sp1Repo: string;
    wormholeRepo: string;
    dogeRpcUser: string;
    dogeRpcPassword: string;
};

const SCRIPT_DIR = import.meta.dir;
const REPO_ROOT = path.resolve(SCRIPT_DIR, "..");
const DEFAULT_PROJECTS_DIR = path.resolve(REPO_ROOT, "..");
const STATE_ROOT = path.resolve(
    process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"),
    "psy-doge-local",
);
const ACTIVE_STATE_PATH = path.join(STATE_ROOT, "active.json");
const DATA_ROOT = path.join(STATE_ROOT, "data");
const DOGE_DATA_DIR = path.join(DATA_ROOT, "dogecoin-regtest");
const ELECTRS_DATA_DIR = path.join(DATA_ROOT, "electrs-regtest");
const SOLANA_LEDGER_DIR = path.join(DATA_ROOT, "solana-ledger");
const DOGE_RPC_URL = "http://127.0.0.1:22555";
const SOLANA_RPC_URL = "http://127.0.0.1:8899";
const ELECTRS_HTTP_URL = "http://127.0.0.1:3002";
const BRIDGE_STATE_PDA = "9vzbk8X27e6VRcCPWCyxZsa2DV6GLQ3y9e1mXzfAgUdX";
const WORMHOLE_COMMIT = "c5e1f791e0a84b133ad7ad2fb98c6ef2fe4900b1";
const WORMHOLE_CORE_ID = "Bridge1p5gheXUvJ6jGWGeCsgPKgnE3YgdGKRVCMY9o";
const WORMHOLE_SHIM_ID = "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";
const WORMHOLE_NAMESPACE = "wormhole";
const WORMHOLE_CONTEXT = "ci";
const WORMHOLE_PORTS = { guardianGrpc: 7070, guardianRest: 7071, spyGrpc: 7072 } as const;
const PUBLIC_WORMHOLE_DEVNET_CORE_ID = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";
const PUBLIC_WORMHOLE_DEVNET_SHIM_ID = "EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX";
const SOLANA_GENESIS_HASHES = {
    devnet: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
    testnet: "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
} as const;
const UPGRADEABLE_LOADER_ID = "BPFLoaderUpgradeab1e11111111111111111111111";
const PUBLIC_PROGRAM_NAMES = ["doge-bridge", "pending-mint-buffer", "txo-buffer", "generic-buffer", "manual-claim"] as const;

const PORTS = {
    dogeRpc: 22555,
    dogeP2p: 18444,
    electrsHttp: 3002,
    electrum: 60401,
    electrsMetrics: 24224,
    solanaRpc: 8899,
    solanaWs: 8900,
    solanaFaucet: 9900,
    legacyRedis: 6379,
} as const;

function usage(): string {
    return `
Doge local bridge launcher and public Solana deployer (Bun)

Usage:
  bun doge/locSetupDoge.ts [local options]
  bun doge/locSetupDoge.ts --deploy --cluster devnet --rpc-url <url> --payer <keypair> --program-key-dir <dir> --preflight

Profiles (unchanged local orchestration):
  --profile real-noop         Recommended: Dogecoin regtest + six real/noop Solana programs (default)
  --profile initialized-noop  real-noop plus bridge initialization and three local users
  --profile wormhole          Official pinned Wormhole Guardian + Solana devnet via Tilt/Kubernetes
  --profile legacy-ibc        Isolated Redis sandbox only; visibly dummy/incompatible, no legacy workers

Public deployment (custom programs only; canonical Wormhole programs are never deployed):
  --deploy                    Select the public deployment workflow
  --cluster <name>            local|devnet|testnet|custom (required with --deploy)
  --rpc-url <url>             RPC override; required for custom
  --payer <path>              Fee payer keypair file (required; manifest records pubkey, not secret)
  --upgrade-authority <path>  Upgrade-authority keypair (default: payer)
  --program-key-dir <path>    Directory containing doge-bridge.json, pending-mint.json,
                              txo-buffer.json, generic-buffer.json, manual-claim.json
  --doge-bridge-keypair <p>   Individual public program keypair overrides:
  --pending-mint-keypair <p>  doge-bridge, pending-mint, txo-buffer, generic-buffer,
  --txo-buffer-keypair <p>    and manual-claim (all five required without --program-key-dir)
  --generic-buffer-keypair <p>
  --manual-claim-keypair <p>
  --wormhole-core-id <id>     Devnet default: official public testnet Core 3u8hJUV...;
                              testnet/custom require an explicit source-grounded ID
  --wormhole-shim-id <id>     Devnet default: official Post Message Shim EtZMZM...;
                              testnet/custom require an explicit source-grounded ID
  --deployment-policy <p>     new|upgrade|auto (default: auto); mismatches fail closed
  --build / --no-build        Build missing public ELFs (default) or require existing artifacts
  --rebuild-programs          Rebuild all public ELFs before deployment
  --initialize                Initialize bridge after verified deployment
  --config <path>             Initialization Dogecoin config JSON
  --keys-dir <path>           Existing operator/fee_spender/doge_mint keypairs for public init
  --output <path>             Initialization result JSON
  --manifest <path>           Atomic manifest output (must not already exist)
  --commitment <level>        processed|confirmed|finalized (default: confirmed)
  --airdrop <sol>             Explicitly request this SOL amount; never implicit
  --yes                       Required for build/deploy/upgrade/airdrop/initialize mutations
  --preflight, --dry-run      Read-only checks and exact plan; no subprocess mutation
  --deployment-smoke-test     Offline atomic-manifest and ELF hash verification smoke

Local components and lifecycle:
  --dogecoin / --no-dogecoin  Enable/disable Dogecoin regtest
  --electrs                   Start electrs-doge and wait for indexed tip
  --solana / --no-solana      Enable/disable local Solana validator
  --initialize                Initialize the local bridge
  --create-users              Create user1/user2/user3 locally
  --noop-monitor              Run the noop-shim monitor
  --legacy-ibc                Isolated Redis-only legacy sandbox
  --only <csv>                Replace profile components
  --teardown                  Stop only launcher-recorded PIDs/container IDs
  --purge                     Teardown and remove launcher-owned state
  --projects-dir <path>       Sibling repository root
  --bridge-repo <path>        psy-doge-solana-bridge override
  --dogecoin-repo <path>      Dogecoin Core source override
  --electrs-repo <path>       electrs-doge source override
  --sp1-repo <path>           psy-bridge-sp1 override
  --wormhole-repo <path>      Pinned official Wormhole repo override
  --doge-rpc-user <user>      Local regtest RPC user
  --doge-rpc-password <pass>  Local regtest RPC password
  -h, --help                  Show help

Examples:
  bun doge/locSetupDoge.ts --preflight
  bun doge/locSetupDoge.ts --profile initialized-noop
  bun doge/locSetupDoge.ts --profile wormhole --preflight
  bun doge/locSetupDoge.ts --deploy --cluster devnet --rpc-url https://api.devnet.solana.com \\
    --payer ~/.config/solana/devnet.json --program-key-dir ./secure-program-keys --preflight
  bun doge/locSetupDoge.ts --deploy --cluster devnet --rpc-url https://api.devnet.solana.com \\
    --payer ~/.config/solana/devnet.json --program-key-dir ./secure-program-keys \\
    --deployment-policy auto --manifest ./deployments/devnet.json --yes

Safety:
  * Public doge-bridge builds are exactly --no-default-features --features solprogram,wormhole;
    public deployment never builds or deploys mock-zkp/noop-shim.
  * Devnet Wormhole defaults are source-grounded in Wormhole's solana.rs devnet module.
    Bridge1p5... is the local Tilt Core ID and is rejected for public deployment.
  * Public mutation requires --yes. Ownership and upgrade authority are checked before mutation.
  * Every deployed custom ELF is dumped and SHA-256 matched before atomic manifest publication.
`;
}

function fail(message: string): never {
    throw new Error(message);
}

function asString(value: unknown, fallback: string): string {
    return typeof value === "string" && value.length > 0 ? value : fallback;
}

function parseProfile(value: unknown): Profile {
    const profile = asString(value, "real-noop");
    if (!["real-noop", "initialized-noop", "wormhole", "legacy-ibc"].includes(profile)) {
        fail(`Unknown profile '${profile}'. Expected real-noop, initialized-noop, wormhole, or legacy-ibc.`);
    }
    return profile as Profile;
}
function parseDeploymentCluster(value: unknown): DeploymentCluster {
    const cluster = asString(value, "");
    if (!["local", "devnet", "testnet", "custom"].includes(cluster)) fail("--deploy requires --cluster local|devnet|testnet|custom.");
    return cluster as DeploymentCluster;
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

function resolveDeploymentRpc(cluster: DeploymentCluster, value: unknown): string {
    const supplied = asString(value, "");
    if (supplied) return supplied;
    if (cluster === "local") return SOLANA_RPC_URL;
    if (cluster === "devnet") return "https://api.devnet.solana.com";
    if (cluster === "testnet") return "https://api.testnet.solana.com";
    fail("--cluster custom requires --rpc-url.");
}

function resolveOptions(): Options | null {
    const { values } = parseArgs({
        args: Bun.argv.slice(2),
        strict: true,
        allowPositionals: false,
        options: {
            help: { type: "boolean", short: "h" },
            profile: { type: "string" },
            preflight: { type: "boolean" },
            "dry-run": { type: "boolean" },
            "no-build": { type: "boolean" },
            "rebuild-programs": { type: "boolean" },
            build: { type: "boolean" },
            deploy: { type: "boolean" },
            cluster: { type: "string" },
            "rpc-url": { type: "string" },
            payer: { type: "string" },
            "upgrade-authority": { type: "string" },
            "program-key-dir": { type: "string" },
            "doge-bridge-keypair": { type: "string" },
            "pending-mint-keypair": { type: "string" },
            "txo-buffer-keypair": { type: "string" },
            "generic-buffer-keypair": { type: "string" },
            "manual-claim-keypair": { type: "string" },
            "wormhole-core-id": { type: "string" },
            "wormhole-shim-id": { type: "string" },
            "deployment-policy": { type: "string" },
            config: { type: "string" },
            "keys-dir": { type: "string" },
            output: { type: "string" },
            manifest: { type: "string" },
            commitment: { type: "string" },
            yes: { type: "boolean" },
            airdrop: { type: "string" },
            "deployment-smoke-test": { type: "boolean" },
            teardown: { type: "boolean" },
            purge: { type: "boolean" },
            dogecoin: { type: "boolean" },
            "no-dogecoin": { type: "boolean" },
            electrs: { type: "boolean" },
            solana: { type: "boolean" },
            "no-solana": { type: "boolean" },
            initialize: { type: "boolean" },
            "create-users": { type: "boolean" },
            "noop-monitor": { type: "boolean" },
            "legacy-ibc": { type: "boolean" },
            only: { type: "string" },
            "projects-dir": { type: "string" },
            "bridge-repo": { type: "string" },
            "dogecoin-repo": { type: "string" },
            "electrs-repo": { type: "string" },
            "sp1-repo": { type: "string" },
            "wormhole-repo": { type: "string" },
            "doge-rpc-user": { type: "string" },
            "doge-rpc-password": { type: "string" },
        },
    });

    if (values.help) {
        console.log(usage());
        return null;
    }
    if (values.dogecoin && values["no-dogecoin"]) fail("Use only one of --dogecoin and --no-dogecoin.");
    if (values.solana && values["no-solana"]) fail("Use only one of --solana and --no-solana.");
    if (values.build && values["no-build"]) fail("Use only one of --build and --no-build.");

    const profile = parseProfile(values.profile);
    const projectsDir = path.resolve(asString(values["projects-dir"], DEFAULT_PROJECTS_DIR));
    const bridgeRepo = path.resolve(asString(values["bridge-repo"], path.join(projectsDir, "psy-doge-solana-bridge")));
    let deploy: DeploymentOptions | undefined;
    if (values.deploy) {
        if (values.teardown || values.purge || values.only || values.profile) fail("--deploy cannot be combined with local profile/lifecycle selection.");
        const cluster = parseDeploymentCluster(values.cluster);
        const payerKeypair = path.resolve(asString(values.payer, ""));
        if (!values.payer) fail("--deploy requires --payer <keypair path>.");
        const defaultCore = cluster === "devnet" ? PUBLIC_WORMHOLE_DEVNET_CORE_ID : "";
        const defaultShim = cluster === "devnet" ? PUBLIC_WORMHOLE_DEVNET_SHIM_ID : "";
        const wormholeCoreId = asString(values["wormhole-core-id"], defaultCore);
        const wormholeShimId = asString(values["wormhole-shim-id"], defaultShim);
        if (!wormholeCoreId || !wormholeShimId) fail(`--cluster ${cluster} requires explicit --wormhole-core-id and --wormhole-shim-id unless using the source-grounded devnet defaults.`);
        if (cluster !== "local" && wormholeCoreId === WORMHOLE_CORE_ID) fail(`Public deployment rejects local Tilt Core ID ${WORMHOLE_CORE_ID}. Supply the official network Core ID.`);
        if (cluster === "devnet" && wormholeShimId !== PUBLIC_WORMHOLE_DEVNET_SHIM_ID) fail(`Devnet shim ${wormholeShimId} does not match the official public Post Message Shim ${PUBLIC_WORMHOLE_DEVNET_SHIM_ID}.`);
        const airdropValue = asString(values.airdrop, "");
        const airdropSol = airdropValue ? Number(airdropValue) : undefined;
        if (airdropSol !== undefined && (!Number.isFinite(airdropSol) || airdropSol <= 0)) fail("--airdrop must be a positive SOL amount.");
        const programKeyDir = values["program-key-dir"] ? path.resolve(String(values["program-key-dir"])) : undefined;
        deploy = {
            cluster,
            rpcUrl: resolveDeploymentRpc(cluster, values["rpc-url"]),
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
            wormholeCoreId,
            wormholeShimId,
            policy: parseDeploymentPolicy(values["deployment-policy"]),
            initialize: Boolean(values.initialize),
            configPath: path.resolve(asString(values.config, path.join(bridgeRepo, "bridge-config/doge_config.json"))),
            keysDir: path.resolve(asString(values["keys-dir"], path.join(bridgeRepo, "bridge-config/keys"))),
            outputPath: path.resolve(asString(values.output, path.join(bridgeRepo, "bridge-config/bridge-output.json"))),
            manifestPath: path.resolve(asString(values.manifest, path.join(REPO_ROOT, "deployments", `${cluster}-doge-bridge.json`))),
            commitment: parseCommitment(values.commitment),
            yes: Boolean(values.yes),
            airdropSol,
        };
    }
    let components = new Set<Component>();
    if (profile === "real-noop" || profile === "initialized-noop") {
        components.add("dogecoin");
        components.add("solana");
    }
    if (profile === "initialized-noop") {
        components.add("initialize");
        components.add("users");
    }
    if (profile === "legacy-ibc") components.add("legacy-ibc");

    if (values.only) {
        components = new Set<Component>();
        const allowed = new Set<Component>(["dogecoin", "electrs", "solana", "initialize", "users", "noop-monitor", "legacy-ibc"]);
        for (const raw of values.only.split(",")) {
            const component = raw.trim() as Component;
            if (!allowed.has(component)) fail(`Unknown --only component '${raw.trim()}'.`);
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
    if (values["legacy-ibc"]) components.add("legacy-ibc");
    if (components.has("electrs")) components.add("dogecoin");
    if (components.has("users")) components.add("initialize");
    if (components.has("initialize")) components.add("solana");
    if (components.has("noop-monitor")) components.add("solana");

    return {
        profile,
        dryRun: Boolean(values.preflight || values["dry-run"]),
        noBuild: Boolean(values["no-build"]),
        rebuildPrograms: Boolean(values["rebuild-programs"]),
        deploy,
        deploymentSmokeTest: Boolean(values["deployment-smoke-test"]),
        teardown: Boolean(values.teardown || values.purge),
        purge: Boolean(values.purge),
        components: deploy ? new Set<Component>() : components,
        projectsDir,
        bridgeRepo,
        dogecoinRepo: path.resolve(asString(values["dogecoin-repo"], path.join(projectsDir, "dogecoin"))),
        electrsRepo: path.resolve(asString(values["electrs-repo"], path.join(projectsDir, "electrs-doge"))),
        sp1Repo: path.resolve(asString(values["sp1-repo"], path.join(projectsDir, "psy-bridge-sp1"))),
        wormholeRepo: path.resolve(asString(values["wormhole-repo"], path.join(projectsDir, "wormhole"))),
        dogeRpcUser: asString(values["doge-rpc-user"], "doge"),
        dogeRpcPassword: asString(values["doge-rpc-password"], "doge"),
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

function runDeploymentSmokeTest(): void {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "doge-deployment-smoke-"));
    try {
        const localElf = path.join(root, "local.so");
        const dumpedElf = path.join(root, "dumped.so");
        const manifestPath = path.join(root, "nested", "manifest.json");
        fs.writeFileSync(localElf, Buffer.from("verified-sbf-elf"));
        fs.copyFileSync(localElf, dumpedElf);
        const localHash = fileSha256(localElf);
        const dumpedHash = fileSha256(dumpedElf);
        if (localHash !== dumpedHash) fail("Deployment smoke hash comparison failed.");
        assertWritableNewPath(manifestPath);
        writeJsonAtomic(manifestPath, { localHash, dumpedHash, verified: true });
        const value = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as { verified?: boolean; localHash?: string };
        if (!value.verified || value.localHash !== localHash) fail("Deployment smoke atomic manifest validation failed.");
        if (fs.readdirSync(path.dirname(manifestPath)).some((name) => name.endsWith(".tmp"))) fail("Deployment smoke left a temporary manifest.");
        console.log(`[deployment-smoke-test] PASS — SHA-256 ${localHash}; atomic manifest ${manifestPath}`);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
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

async function electrsHeight(): Promise<number | null> {
    try {
        const response = await fetch(`${ELECTRS_HTTP_URL}/blocks/tip/height`, { signal: AbortSignal.timeout(2_000) });
        if (!response.ok) return null;
        const height = Number.parseInt((await response.text()).trim(), 10);
        return Number.isFinite(height) ? height : null;
    } catch {
        return null;
    }
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

    async spawn(command: string[], role: string, cwd: string, daemon: boolean): Promise<Bun.Subprocess> {
        ensureDirectory(this.runDir);
        const safeRole = role.replace(/[^A-Za-z0-9_.-]/g, "-");
        const stdoutLog = path.join(this.runDir, `${safeRole}.stdout.log`);
        const stderrLog = path.join(this.runDir, `${safeRole}.stderr.log`);
        fs.writeFileSync(stdoutLog, "");
        fs.writeFileSync(stderrLog, "");
        console.log(`[start:${role}] ${commandText(command)}`);
        const proc = Bun.spawn(command, {
            cwd,
            env: { ...process.env, NO_PROXY: "localhost,127.0.0.1", no_proxy: "localhost,127.0.0.1" },
            stdout: Bun.file(stdoutLog),
            stderr: Bun.file(stderrLog),
        });
        const startTicks = await waitFor<string>(`${role} PID registration`, 2_000, async () => readStartTicks(proc.pid));
        const record: ProcessRecord = { role, pid: proc.pid, startTicks, command, cwd, stdoutLog, stderrLog };
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
        if (state.wormhole && removeData) {
            console.log(`[purge:wormhole] Removing launcher-owned Kubernetes namespace ${state.wormhole.namespace}`);
            const ns = Bun.spawnSync(["kubectl", "delete", "namespace", state.wormhole.namespace, "--ignore-not-found"], { stdout: "pipe", stderr: "pipe" });
            if (ns.exitCode !== 0) console.warn(`[purge:wormhole] kubectl delete namespace failed: ${ns.stderr.toString().trim() || ns.stdout.toString().trim()}`);
            else console.log(`[purge:wormhole] Namespace ${state.wormhole.namespace} removed.`);
        }
        if (removeData) {
            fs.rmSync(STATE_ROOT, { recursive: true, force: true });
            console.log(`[purge] Removed ${STATE_ROOT}`);
        }
    }

    async resolveProgramIds(): Promise<void> {
        const keygen = executableInPath("solana-keygen");
        if (!keygen) fail("Missing solana-keygen. Install the Solana/Agave CLI tools.");
        for (const program of this.programs) {
            if (!fs.existsSync(program.keypair)) fail(`Missing program keypair: ${program.keypair}`);
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
        if (this.options.deploy) {
            return [
                ["cargo", "build-sbf", "--", "--no-default-features", "--features", "solprogram,wormhole", "-p", "doge-bridge"],
                ["cargo", "build-sbf", "--", "--no-default-features", "--features", "solprogram", "-p", "manual-claim"],
                ["cargo", "build-sbf", "--", "--no-default-features", "-p", "pending-mint-buffer", "-p", "txo-buffer", "-p", "generic-buffer"],
            ];
        }
        const shimFeature = this.options.profile === "wormhole" ? "wormhole" : "noopshim";
        return [
            ["cargo", "build-sbf", "--", "--no-default-features", "--features", `solprogram,${shimFeature}`, "-p", "doge-bridge"],
            ["cargo", "build-sbf", "--", "--no-default-features", "--features", "solprogram", "-p", "manual-claim"],
            ["cargo", "build-sbf", "--", "--no-default-features", "-p", "pending-mint-buffer", "-p", "txo-buffer", "-p", "generic-buffer", "-p", "noop-shim"],
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
            "-vv",
        ];
    }

    solanaCommand(): string[] {
        const command = [
            "solana-test-validator",
            "--reset",
            "--ledger", SOLANA_LEDGER_DIR,
            "--bind-address", "127.0.0.1",
            "--gossip-host", "127.0.0.1",
            "--rpc-port", String(PORTS.solanaRpc),
            "--faucet-port", String(PORTS.solanaFaucet),
            "--compute-unit-limit", "1400000",
        ];
        for (const program of this.programs) command.push("--bpf-program", program.keypair, program.elf);
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

    wormholeTiltCommand(): string[] {
        return ["tilt", "up", "--", "--solana", "--num=1"];
    }

    wormholeDeployCommand(program: Program): string[] {
        return [
            "solana", "program", "deploy",
            "--url", SOLANA_RPC_URL,
            "--keypair", path.join(this.options.wormholeRepo, "solana/keys/solana-devnet.json"),
            "--program-id", program.keypair,
            program.elf,
        ];
    }

    deploymentCommand(program: Program): string[] {
        const deploy = this.options.deploy!;
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
        return this.capture(["solana-keygen", "pubkey", keypair], REPO_ROOT);
    }

    async deploymentAccount(id: string): Promise<any | null> {
        const deploy = this.options.deploy!;
        const result = await jsonRpc(deploy.rpcUrl, "getAccountInfo", [id, { encoding: "base64", commitment: deploy.commitment }]);
        return result?.value || null;
    }

    programShow(id: string): Record<string, string> {
        const deploy = this.options.deploy!;
        const output = this.capture(["solana", "program", "show", id, "--url", deploy.rpcUrl, "--output", "json"], REPO_ROOT);
        return JSON.parse(output) as Record<string, string>;
    }

    async preflightDeployment(): Promise<{ genesisHash: string; solanaVersion: string; payerPubkey: string; balanceLamports: number; actions: Record<string, "deploy" | "upgrade"> }> {
        const deploy = this.options.deploy!;
        const errors: string[] = [];
        if (!fs.existsSync(this.options.bridgeRepo)) errors.push(`Missing bridge repository: ${this.options.bridgeRepo}`);
        for (const tool of ["solana", "solana-keygen"]) if (!executableInPath(tool)) errors.push(`Missing required command '${tool}'.`);
        for (const keypair of [deploy.payerKeypair, deploy.upgradeAuthorityKeypair]) if (!fs.existsSync(keypair)) errors.push(`Missing keypair: ${keypair}`);
        if (!deploy.programKeyDir && PUBLIC_PROGRAM_NAMES.some((name) => !deploy.programKeypairs[name])) errors.push("Supply --program-key-dir or every individual public program keypair.");
        for (const program of this.programs) if (!fs.existsSync(program.keypair)) errors.push(`Missing program keypair: ${program.keypair}`);
        if (deploy.initialize) {
            if (!fs.existsSync(deploy.configPath)) errors.push(`Missing initialization config: ${deploy.configPath}`);
            for (const name of ["operator.json", "fee_spender.json", "doge_mint.json"]) if (!fs.existsSync(path.join(deploy.keysDir, name))) errors.push(`Public initialization requires existing ${path.join(deploy.keysDir, name)}; key generation is not implicit.`);
            if (fs.existsSync(deploy.outputPath)) errors.push(`Refusing to overwrite existing initialization output: ${deploy.outputPath}`);
        }
        try { assertWritableNewPath(deploy.manifestPath); } catch (error) { errors.push(`Manifest path is not safely writable: ${String(error)}`); }
        if (deploy.manifestPath === deploy.outputPath) errors.push("--manifest and --output must be different paths.");
        try { if (deploy.initialize) assertWritableNewPath(deploy.outputPath); } catch (error) { errors.push(`Initialization output path is not safely writable: ${String(error)}`); }
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
        const bridgeCli = path.join(this.options.bridgeRepo, "target/debug/doge-bridge-cli");
        const cliBuildRequired = deploy.initialize && !firstExecutable([bridgeCli]);
        if (cliBuildRequired && this.options.noBuild) errors.push(`Bridge CLI is missing and --no-build was set: ${bridgeCli}`);
        if (cliBuildRequired && !executableInPath("cargo")) errors.push("Building the bridge CLI requires 'cargo'.");
        if (errors.length > 0) fail(`Deployment preflight failed before network mutation:\n  - ${errors.join("\n  - ")}`);

        await this.resolveProgramIds();
        const payerPubkey = this.keypairPubkey(deploy.payerKeypair);
        const authorityPubkey = this.keypairPubkey(deploy.upgradeAuthorityKeypair);
        for (const program of this.programs) if ([deploy.wormholeCoreId, deploy.wormholeShimId, WORMHOLE_CORE_ID].includes(program.id!)) fail(`Custom program ${program.name} collides with canonical/local-only program ID ${program.id}.`);
        if (deploy.initialize && this.programs[0].id !== "DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ") fail(`The current initializer is compiled for doge-bridge DBjo5tqf2uwt4sg9JznSk9SBbEvsLixknN58y3trwCxJ, but the supplied keypair is ${this.programs[0].id}. Refusing mismatched initialization.`);
        const genesisHash = String(await jsonRpc(deploy.rpcUrl, "getGenesisHash"));
        const versionResult = await jsonRpc(deploy.rpcUrl, "getVersion");
        const solanaVersion = String(versionResult?.["solana-core"] || versionResult?.["agave-core"] || "unknown");
        if (deploy.cluster === "devnet" && genesisHash !== SOLANA_GENESIS_HASHES.devnet) fail(`RPC genesis ${genesisHash} is not Solana devnet ${SOLANA_GENESIS_HASHES.devnet}.`);
        if (deploy.cluster === "testnet" && genesisHash !== SOLANA_GENESIS_HASHES.testnet) fail(`RPC genesis ${genesisHash} is not Solana testnet ${SOLANA_GENESIS_HASHES.testnet}.`);
        const balanceLamports = Number(await jsonRpc(deploy.rpcUrl, "getBalance", [payerPubkey, { commitment: deploy.commitment }]).then((value) => value?.value));
        if (!Number.isFinite(balanceLamports)) fail("Could not determine payer balance.");
        const estimatedLamports = this.programs.reduce((sum, program) => sum + (fs.existsSync(program.elf) ? fs.statSync(program.elf).size * 20 : 2_000_000), 0) + 5_000_000_000;
        const projectedBalance = balanceLamports + Math.floor((deploy.airdropSol || 0) * 1_000_000_000);
        if (projectedBalance < estimatedLamports) fail(`Payer balance plus requested airdrop is ${(projectedBalance / 1e9).toFixed(3)} SOL, below conservative estimate ${(estimatedLamports / 1e9).toFixed(3)} SOL.`);
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
        if (cliBuildRequired) console.log("  (build initializer) cargo build -p doge-bridge-cli");
        if (deploy.airdropSol !== undefined) console.log(`  (explicit airdrop) solana airdrop ${deploy.airdropSol} ${payerPubkey} --url ${deploy.rpcUrl}`);
        for (const program of this.programs) console.log(`  (${actions[program.name]}) ${commandText(this.deploymentCommand(program))}`);
        for (const program of this.programs) console.log(`  (verify) solana program dump ${program.id} <dump> --url ${deploy.rpcUrl}; SHA-256 == ${program.elf}`);
        if (deploy.initialize) console.log(`  (initialize) doge-bridge-cli --rpc-url ${deploy.rpcUrl} -k ${deploy.payerKeypair} initialize-from-doge-data --config ${deploy.configPath} --keys-dir ${deploy.keysDir} --output ${deploy.outputPath} --yes`);
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
        const commandStatus: Array<{ command: string; status: string }> = [];
        if (!this.options.noBuild) {
            for (const [index, command] of this.bridgeBuildCommands().entries()) {
                await this.run(command, `public-build-${index + 1}`, this.options.bridgeRepo);
                commandStatus.push({ command: commandText(command), status: "built" });
            }
            const provenancePath = path.join(path.dirname(this.programs[0].elf), "doge-public-build.json");
            const temp = `${provenancePath}.${process.pid}.tmp`;
            fs.writeFileSync(temp, `${JSON.stringify({
                timestamp: new Date().toISOString(),
                features: "solprogram,wormhole; no defaults; no mock-zkp; no noop-shim",
                commands: this.bridgeBuildCommands().map(commandText),
                programs: Object.fromEntries(this.programs.map((program) => [program.name, { elf: program.elf, sha256: fileSha256(program.elf) }])),
            }, null, 2)}\n`, { mode: 0o600 });
            fs.renameSync(temp, provenancePath);
            commandStatus.push({ command: `write ${provenancePath}`, status: "build-provenance" });
        }
        for (const program of this.programs) if (!fs.existsSync(program.elf)) fail(`Public build did not produce ${program.elf}`);
        if (deploy.initialize && !firstExecutable([path.join(this.options.bridgeRepo, "target/debug/doge-bridge-cli")])) {
            const command = ["cargo", "build", "-p", "doge-bridge-cli"];
            await this.run(command, "build-public-bridge-cli", this.options.bridgeRepo);
            commandStatus.push({ command: commandText(command), status: "built" });
        }
        if (deploy.airdropSol !== undefined) {
            const command = ["solana", "airdrop", String(deploy.airdropSol), preflight.payerPubkey, "--url", deploy.rpcUrl];
            await this.run(command, "public-airdrop", REPO_ROOT);
            commandStatus.push({ command: commandText(command), status: "airdrop" });
        }
        for (const program of this.programs) {
            const command = this.deploymentCommand(program);
            await this.run(command, `${preflight.actions[program.name]}-${program.name}`, this.options.bridgeRepo);
            commandStatus.push({ command: commandText(command), status: preflight.actions[program.name] });
        }
        const deployedPrograms: Record<string, unknown> = {};
        for (const program of this.programs) {
            const dumpPath = path.join(this.runDir, `${program.name}-deployed.so`);
            await this.run(["solana", "program", "dump", program.id!, dumpPath, "--url", deploy.rpcUrl], `dump-${program.name}`, this.options.bridgeRepo);
            commandStatus.push({ command: `solana program dump ${program.id} ${dumpPath} --url ${deploy.rpcUrl}`, status: "verified" });
            const localSha256 = fileSha256(program.elf);
            const deployedSha256 = fileSha256(dumpPath);
            if (localSha256 !== deployedSha256) fail(`${program.name} deployed ELF hash ${deployedSha256} does not match local ${localSha256}. Manifest not written.`);
            const account = await jsonRpc(deploy.rpcUrl, "getAccountInfo", [program.id, { encoding: "base64", commitment: deploy.commitment }]);
            deployedPrograms[program.name] = { id: program.id, action: preflight.actions[program.name], keypairPath: program.keypair, localElf: program.elf, dumpedElf: dumpPath, localSha256, deployedSha256, slot: account?.context?.slot };
        }
        let initializationSignature: string | null = null;
        if (deploy.initialize) {
            const cli = await this.ensureBridgeCli();
            await this.run([cli, "--rpc-url", deploy.rpcUrl, "-k", deploy.payerKeypair, "initialize-from-doge-data", "--config", deploy.configPath, "--keys-dir", deploy.keysDir, "--output", deploy.outputPath, "--yes"], "public-initialize", this.options.bridgeRepo);
            commandStatus.push({ command: `${cli} --rpc-url ${deploy.rpcUrl} -k ${deploy.payerKeypair} initialize-from-doge-data --config ${deploy.configPath} --keys-dir ${deploy.keysDir} --output ${deploy.outputPath} --yes`, status: "initialized" });
            const output = JSON.parse(fs.readFileSync(deploy.outputPath, "utf8")) as { initialize_tx_signature?: string };
            initializationSignature = output.initialize_tx_signature || null;
        }
        const bridgeState = await jsonRpc(deploy.rpcUrl, "getAccountInfo", [BRIDGE_STATE_PDA, { encoding: "base64", commitment: deploy.commitment }]);
        if (deploy.initialize && !bridgeState?.value) fail(`Bridge initialization returned but state ${BRIDGE_STATE_PDA} is absent. Manifest not written.`);
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
            initialization: { requested: deploy.initialize, signature: initializationSignature, bridgeStatePda: BRIDGE_STATE_PDA, slot: bridgeState?.context?.slot },
            commands: commandStatus,
            status: "verified",
        });
        console.log(`[deploy] PASS — verified ${this.programs.length} custom programs; atomic manifest ${deploy.manifestPath}`);
    }

    async preflightWormhole(): Promise<void> {
        if (this.options.components.size > 0) fail("The wormhole profile owns its official Solana devnet; component flags/--only are not supported with --profile wormhole.");
        const errors: string[] = [];
        const repo = this.options.wormholeRepo;
        if (!fs.existsSync(repo)) {
            errors.push(`Missing official Wormhole repository: ${repo}. Clone wormhole-foundation/wormhole at ${WORMHOLE_COMMIT}, or pass --wormhole-repo <path>.`);
        } else {
            for (const relative of ["Tiltfile", "DEVELOP.md", "devnet/node.yaml", "devnet/spy.yaml", "devnet/solana-devnet.yaml", "proto/spy/v1/spy.proto", "proto/publicrpc/v1/publicrpc.proto", "solana/keys/solana-devnet.json"]) {
                if (!fs.existsSync(path.join(repo, relative))) errors.push(`Official Wormhole checkout is missing required path: ${path.join(repo, relative)}`);
            }
            const head = this.syncOutput(["git", "rev-parse", "HEAD"], repo);
            if (!head.ok) errors.push(`Cannot read Wormhole git HEAD at ${repo}: ${head.stderr || head.stdout}`);
            else if (head.stdout !== WORMHOLE_COMMIT) errors.push(`Wrong Wormhole commit at ${repo}: expected ${WORMHOLE_COMMIT}, found ${head.stdout}.`);
            const tracked = this.syncOutput(["git", "status", "--porcelain", "--untracked-files=no"], repo);
            if (!tracked.ok) errors.push(`Cannot inspect Wormhole tracked files at ${repo}: ${tracked.stderr || tracked.stdout}`);
            else if (tracked.stdout) errors.push(`Wormhole checkout has tracked modifications; restore exact commit ${WORMHOLE_COMMIT} before orchestration.`);
            try {
                const tiltfile = fs.readFileSync(path.join(repo, "Tiltfile"), "utf8");
                const solanaYaml = fs.readFileSync(path.join(repo, "devnet/solana-devnet.yaml"), "utf8");
                for (const expected of ["--solanaContract", WORMHOLE_CORE_ID, "--solanaShimContract", WORMHOLE_SHIM_ID]) {
                    if (!tiltfile.includes(expected)) errors.push(`Pinned Tiltfile is missing canonical Solana watcher setting '${expected}'.`);
                }
                for (const expected of [WORMHOLE_CORE_ID, "/opt/solana/deps/bridge.so", WORMHOLE_SHIM_ID, "/opt/solana/deps/wormhole_post_message_shim.so"]) {
                    if (!solanaYaml.includes(expected)) errors.push(`Pinned Solana devnet manifest is missing canonical program entry '${expected}'.`);
                }
            } catch (error) {
                errors.push(`Cannot validate canonical Core/shim sources: ${String(error)}`);
            }
        }

        if (!fs.existsSync(this.options.bridgeRepo)) errors.push(`Missing bridge repository: ${this.options.bridgeRepo}`);
        const requiredTools = ["git", "tilt", "kubectl", "docker", "solana", "solana-keygen"];
        for (const tool of requiredTools) if (!executableInPath(tool)) errors.push(`Missing required command '${tool}'.`);
        if (executableInPath("docker")) {
            const docker = this.syncOutput(["docker", "info"], REPO_ROOT);
            if (!docker.ok) errors.push(`Docker daemon is unavailable: ${docker.stderr || docker.stdout || "docker info failed"}`);
        }
        if (executableInPath("kubectl")) {
            const context = this.syncOutput(["kubectl", "config", "current-context"], REPO_ROOT);
            if (!context.ok) errors.push(`Cannot read current Kubernetes context: ${context.stderr || context.stdout}`);
            else if (context.stdout !== WORMHOLE_CONTEXT) errors.push(`Wrong Kubernetes context '${context.stdout || "<empty>"}'; pinned Tiltfile permits '${WORMHOLE_CONTEXT}'. Select/create it before running.`);
            const cluster = this.syncOutput(["kubectl", "cluster-info"], REPO_ROOT);
            if (!cluster.ok) errors.push(`Kubernetes cluster is unreachable: ${cluster.stderr || cluster.stdout}`);
            const namespace = this.syncOutput(["kubectl", "get", "namespace", WORMHOLE_NAMESPACE, "--ignore-not-found", "-o", "name"], REPO_ROOT);
            if (!namespace.ok) errors.push(`Cannot inspect Kubernetes namespace '${WORMHOLE_NAMESPACE}': ${namespace.stderr || namespace.stdout}`);
            else if (namespace.stdout) errors.push(`Kubernetes namespace '${WORMHOLE_NAMESPACE}' already exists. This launcher will not adopt or modify an unowned Wormhole deployment; remove it yourself or use the owning launcher's --purge.`);
        }

        if (executableInPath("solana-keygen") && fs.existsSync(this.options.bridgeRepo)) {
            try { await this.resolveProgramIds(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
            for (const program of this.programs) {
                if (program.id === WORMHOLE_CORE_ID || program.id === WORMHOLE_SHIM_ID) errors.push(`Custom program ${program.name} must not replace canonical Core/shim ID ${program.id}.`);
            }
            const missingElfs = this.programs.filter((program) => !fs.existsSync(program.elf));
            if ((missingElfs.length > 0 || this.options.rebuildPrograms) && this.options.noBuild) {
                errors.push(`Wormhole bridge ELF build required but --no-build was set: ${missingElfs.map((program) => program.elf).join(", ") || "--rebuild-programs requested"}`);
            }
            if (missingElfs.length > 0 || this.options.rebuildPrograms) {
                if (!executableInPath("cargo")) errors.push("Building Wormhole bridge ELFs requires 'cargo'.");
                if (!executableInPath("cargo-build-sbf")) errors.push("Building Wormhole bridge ELFs requires 'cargo-build-sbf'.");
            }
        }

        const reservedPorts = [PORTS.solanaRpc, PORTS.solanaWs, PORTS.solanaFaucet, WORMHOLE_PORTS.guardianGrpc, WORMHOLE_PORTS.guardianRest, WORMHOLE_PORTS.spyGrpc, 10350];
        const portStatus = await Promise.all(reservedPorts.map(async (port) => [port, await portOpen(port)] as const));
        for (const [port, open] of portStatus) if (open) errors.push(`Required Wormhole/Tilt host port ${port} is already occupied; no existing service will be adopted or killed.`);
        if (errors.length > 0) fail(`Wormhole preflight failed before spawning services:\n  - ${errors.join("\n  - ")}`);

        const missingElfs = this.programs.filter((program) => !fs.existsSync(program.elf));
        console.log(`[wormhole] official repo ${repo} at exact commit ${WORMHOLE_COMMIT}`);
        console.log(`[wormhole] Kubernetes context ${WORMHOLE_CONTEXT}; launcher-owned namespace to be created: ${WORMHOLE_NAMESPACE}`);
        console.log("\n[plan]");
        if (missingElfs.length > 0 || this.options.rebuildPrograms) for (const command of this.bridgeBuildCommands()) console.log(`  (real build) ${commandText(command)}`);
        console.log(`  (start official stack) ${commandText(this.wormholeTiltCommand())}`);
        console.log(`  (ready) kubectl -n ${WORMHOLE_NAMESPACE} wait --for=condition=Ready pod -l app=solana-devnet --timeout=20m`);
        console.log(`  (ready) kubectl -n ${WORMHOLE_NAMESPACE} wait --for=condition=Ready pod -l app=guardian --timeout=20m`);
        console.log(`  (ready) kubectl -n ${WORMHOLE_NAMESPACE} wait --for=condition=Ready pod -l app=spy --timeout=20m`);
        for (const program of this.programs) console.log(`  (deploy custom${program.name === "noop-shim" ? ", unused by wormhole-feature bridge" : ""}) ${commandText(this.wormholeDeployCommand(program))}`);
        console.log(`  (verify canonical) executable ${WORMHOLE_CORE_ID} and ${WORMHOLE_SHIM_ID}; neither is deployed/replaced by this launcher`);
        console.log(`  (observe signed VAA stream; official DEVELOP.md) ${path.join(repo, "tools/bin/grpcurl")} -protoset <(${path.join(repo, "tools/bin/buf")} build -o -) -d '{"filters":[{"emitter_filter":{"emitter_address":"<64-hex-doge-bridge-emitter>","chain_id":"CHAIN_ID_SOLANA"}}]}' -plaintext localhost:${WORMHOLE_PORTS.spyGrpc} spy.v1.SpyRPCService/SubscribeSignedVAA`);
        console.log(`  (retrieve known VAA) curl http://localhost:${WORMHOLE_PORTS.guardianRest}/v1/signed_vaa/1/<64-hex-doge-bridge-emitter>/<sequence>`);
        console.log("  (evidence boundary) A returned Guardian-quorum VAA proves Wormhole observation/signing only; it is not DOGE TSS signing, custody authorization, transaction broadcast, or release.\n");
    }

    async preflight(): Promise<{ dogeRunning: boolean; solanaRunning: boolean; electrsRunning: boolean }> {
        const c = this.options.components;
        console.log(`[profile] ${this.options.profile}`);
        console.log(`[components] ${[...c].join(", ") || "none"}`);
        console.log(`[state] ${STATE_ROOT}`);

        if (this.options.profile === "wormhole") {
            await this.preflightWormhole();
            return { dogeRunning: false, solanaRunning: false, electrsRunning: false };
        }
        if (c.has("legacy-ibc")) {
            console.warn("[legacy-ibc] DUMMY/INCOMPATIBLE sandbox: Redis only; no notifier, processor, dummy prover, or missing submitter service is started.");
        }

        if (c.has("dogecoin") && !fs.existsSync(this.options.dogecoinRepo)) fail(`Missing Dogecoin repository: ${this.options.dogecoinRepo}`);
        if (c.has("electrs") && !fs.existsSync(this.options.electrsRepo)) fail(`Missing electrs-doge repository: ${this.options.electrsRepo}`);
        if (c.has("solana") && !fs.existsSync(this.options.bridgeRepo)) fail(`Missing bridge repository: ${this.options.bridgeRepo}`);
        if ((c.has("solana") || c.has("initialize") || c.has("noop-monitor")) && !fs.existsSync(this.options.sp1Repo)) fail(`Missing SP1 repository: ${this.options.sp1Repo}`);

        const requiredTools = new Set<string>();
        if (c.has("solana")) ["solana", "solana-keygen", "solana-test-validator"].forEach((tool) => requiredTools.add(tool));
        if (c.has("legacy-ibc")) requiredTools.add("docker");
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

        if (c.has("solana")) {
            const sp1Bins = [path.join(this.options.sp1Repo, "target/release/gen-proof"), path.join(this.options.sp1Repo, "target/release/gen-withdrawal-proof")];
            if (sp1Bins.some((binary) => !firstExecutable([binary]))) {
                if (this.options.noBuild) fail(`SP1 one-shot binaries are missing and --no-build was set: ${sp1Bins.join(", ")}`);
                if (!executableInPath("cargo")) fail("Building SP1 one-shot tools requires cargo.");
            }
        }

        const dogeRpcOpen = await portOpen(PORTS.dogeRpc);
        const dogeP2pOpen = await portOpen(PORTS.dogeP2p);
        if (c.has("dogecoin")) {
            if (dogeRpcOpen && !dogeRunning) fail(`Port ${PORTS.dogeRpc} is occupied by a service that is not compatible Dogecoin regtest RPC.`);
            if (!dogeRunning && dogeP2pOpen) fail(`Dogecoin P2P port ${PORTS.dogeP2p} is already occupied.`);
            if (dogeRunning && !dogeP2pOpen) fail(`Existing Dogecoin RPC is healthy, but required P2P port ${PORTS.dogeP2p} is not listening.`);
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
        if (c.has("legacy-ibc") && await portOpen(PORTS.legacyRedis)) fail(`Legacy Redis port ${PORTS.legacyRedis} is already occupied; it is never adopted or killed.`);

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
        if (c.has("solana")) {
            if (missingElfs.length > 0 || this.options.rebuildPrograms) for (const command of this.bridgeBuildCommands()) console.log(`  (real build) ${commandText(command)}`);
            console.log(`  ${solanaRunning ? "(reuse)" : "(start)"} ${commandText(this.solanaCommand())}`);
            console.log("  (verify) six executable program accounts; solana program dump doge-bridge; SHA-256 equals local ELF");
            const sp1Bins = [path.join(this.options.sp1Repo, "target/release/gen-proof"), path.join(this.options.sp1Repo, "target/release/gen-withdrawal-proof")];
            if (sp1Bins.some((binary) => !firstExecutable([binary]))) console.log("  (build one-shot only) cargo build --release -p psy-bridge-sp1-script --bin gen-proof --bin gen-withdrawal-proof");
            console.log(`  (checked one-shot, not started) ${sp1Bins.join(", ")}`);
        }
        if (c.has("initialize")) console.log("  (one-shot) doge-bridge-cli initialize-from-doge-data --airdrop --yes");
        if (c.has("users")) console.log("  (one-shot) doge-bridge-cli create-user x3 (missing user files only)");
        if (c.has("noop-monitor")) console.log(`  (start) noop_shim_monitor ${SOLANA_RPC_URL} ${BRIDGE_STATE_PDA}`);
        if (c.has("legacy-ibc")) console.log("  (isolated dummy sandbox) docker run --rm -p 127.0.0.1:6379:6379 redis:7-alpine");
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

        if (c.has("solana") && (this.options.rebuildPrograms || this.programs.some((program) => !fs.existsSync(program.elf)))) {
            for (const [index, command] of this.bridgeBuildCommands().entries()) await this.run(command, `build-bridge-${index + 1}`, this.options.bridgeRepo);
            for (const program of this.programs) if (!fs.existsSync(program.elf)) fail(`Bridge build did not produce ${program.elf}`);
            const manifest = Object.fromEntries(this.programs.map((program) => [program.name, { id: program.id, elf: program.elf, sha256: fileSha256(program.elf) }]));
            fs.writeFileSync(path.join(this.runDir, "real-noop-build.json"), `${JSON.stringify({ features: "solprogram,noopshim; no defaults; no mock-zkp", programs: manifest }, null, 2)}\n`);
        }

        if (c.has("solana")) {
            const genProof = path.join(this.options.sp1Repo, "target/release/gen-proof");
            const genWithdrawal = path.join(this.options.sp1Repo, "target/release/gen-withdrawal-proof");
            if (!firstExecutable([genProof]) || !firstExecutable([genWithdrawal])) {
                await this.run(["cargo", "build", "--release", "-p", "psy-bridge-sp1-script", "--bin", "gen-proof", "--bin", "gen-withdrawal-proof"], "build-sp1-one-shot-tools", this.options.sp1Repo);
            }
            if (!firstExecutable([genProof]) || !firstExecutable([genWithdrawal])) fail("SP1 one-shot build completed but both prover binaries were not found/executable.");
        }
        return { dogeDaemon: doge.daemon, dogeCli: doge.cli, electrs };
    }
    async buildMissingWormhole(): Promise<void> {
        if (this.options.rebuildPrograms || this.programs.some((program) => !fs.existsSync(program.elf))) {
            for (const [index, command] of this.bridgeBuildCommands().entries()) await this.run(command, `build-wormhole-bridge-${index + 1}`, this.options.bridgeRepo);
            for (const program of this.programs) if (!fs.existsSync(program.elf)) fail(`Wormhole bridge build did not produce ${program.elf}`);
            const manifest = Object.fromEntries(this.programs.map((program) => [program.name, { id: program.id, elf: program.elf, sha256: fileSha256(program.elf) }]));
            fs.writeFileSync(path.join(this.runDir, "wormhole-build.json"), `${JSON.stringify({ features: "solprogram,wormhole; no defaults; no mock-zkp; no noop-shim substitution", programs: manifest }, null, 2)}\n`);
        }
    }

    async verifyWormholeAccounts(): Promise<void> {
        for (const id of [WORMHOLE_CORE_ID, WORMHOLE_SHIM_ID]) {
            const value = await jsonRpc(SOLANA_RPC_URL, "getAccountInfo", [id, { encoding: "base64", commitment: "confirmed" }]);
            if (!value?.value?.executable) fail(`Canonical Wormhole program ${id} is absent or not executable on the official Solana devnet.`);
        }
        console.log(`[verify:canonical] Core ${WORMHOLE_CORE_ID}; shim ${WORMHOLE_SHIM_ID} — both executable and preserved.`);
        for (const program of this.programs) {
            const value = await jsonRpc(SOLANA_RPC_URL, "getAccountInfo", [program.id, { encoding: "base64", commitment: "confirmed" }]);
            if (!value?.value?.executable) fail(`Custom program ${program.name} (${program.id}) is absent or not executable after deployment.`);
        }
        const bridge = this.programs[0];
        const dumpPath = path.join(this.runDir, "deployed-doge-bridge.so");
        await this.run(["solana", "program", "dump", bridge.id!, dumpPath, "--url", SOLANA_RPC_URL], "dump-doge-bridge", this.options.bridgeRepo);
        const localHash = fileSha256(bridge.elf);
        const deployedHash = fileSha256(dumpPath);
        fs.writeFileSync(path.join(this.runDir, "wormhole-deployed-program-hashes.json"), `${JSON.stringify({
            dogeBridgeProgramId: bridge.id,
            localElf: bridge.elf,
            dumpedElf: dumpPath,
            localSha256: localHash,
            deployedSha256: deployedHash,
            canonicalCoreId: WORMHOLE_CORE_ID,
            canonicalShimId: WORMHOLE_SHIM_ID,
            allLocalPrograms: Object.fromEntries(this.programs.map((program) => [program.name, { id: program.id, sha256: fileSha256(program.elf) }])),
        }, null, 2)}\n`);
        if (localHash !== deployedHash) fail(`Deployed doge-bridge ELF hash ${deployedHash} does not match local wormhole artifact ${localHash}.`);
        console.log(`[verify:custom] ${this.programs.length} custom programs executable; doge-bridge SHA-256 ${localHash} (solprogram,wormhole)`);
    }

    async startWormhole(): Promise<void> {
        this.state.wormhole = { repo: this.options.wormholeRepo, commit: WORMHOLE_COMMIT, context: WORMHOLE_CONTEXT, namespace: WORMHOLE_NAMESPACE };
        this.persist();
        await this.spawn(this.wormholeTiltCommand(), "tilt-wormhole", this.options.wormholeRepo, true);
        await waitFor("Solana devnet pod readiness", 20 * 60_000, async () => {
            const r = this.syncOutput(["kubectl", "-n", WORMHOLE_NAMESPACE, "wait", "--for=condition=Ready", "pod", "-l", "app=solana-devnet", "--timeout=30s"], REPO_ROOT);
            return r.ok ? r.stdout : null;
        });
        await waitFor("Solana RPC health (Tilt port-forward)", 120_000, async () => await solanaHealthy());
        await waitFor("Solana websocket (Tilt port-forward)", 30_000, async () => await portOpen(PORTS.solanaWs));
        await waitFor("Guardian pod readiness", 20 * 60_000, async () => {
            const r = this.syncOutput(["kubectl", "-n", WORMHOLE_NAMESPACE, "wait", "--for=condition=Ready", "pod", "-l", "app=guardian", "--timeout=30s"], REPO_ROOT);
            return r.ok ? r.stdout : null;
        });
        await waitFor("Guardian REST port", 120_000, async () => await portOpen(WORMHOLE_PORTS.guardianRest));
        await waitFor("Spy pod readiness", 20 * 60_000, async () => {
            const r = this.syncOutput(["kubectl", "-n", WORMHOLE_NAMESPACE, "wait", "--for=condition=Ready", "pod", "-l", "app=spy", "--timeout=30s"], REPO_ROOT);
            return r.ok ? r.stdout : null;
        });
        await waitFor("Spy gRPC port", 120_000, async () => await portOpen(WORMHOLE_PORTS.spyGrpc));
        console.log(`[ready:wormhole] Tilt up; Solana RPC ${SOLANA_RPC_URL}; Guardian REST :${WORMHOLE_PORTS.guardianRest}; Spy gRPC :${WORMHOLE_PORTS.spyGrpc}`);
        for (const program of this.programs) await this.run(this.wormholeDeployCommand(program), `deploy-${program.name}`, this.options.bridgeRepo);
        await this.verifyWormholeAccounts();
        const repo = this.options.wormholeRepo;
        console.log(`[observe:VAA-stream] ${path.join(repo, "tools/bin/grpcurl")} -protoset <(${path.join(repo, "tools/bin/buf")} build -o -) -d '{"filters":[{"emitter_filter":{"emitter_address":"<64-hex-doge-bridge-emitter>","chain_id":"CHAIN_ID_SOLANA"}}]}' -plaintext localhost:${WORMHOLE_PORTS.spyGrpc} spy.v1.SpyRPCService/SubscribeSignedVAA`);
        console.log(`[retrieve:VAA] curl http://localhost:${WORMHOLE_PORTS.guardianRest}/v1/signed_vaa/1/<64-hex-doge-bridge-emitter>/<sequence>`);
        console.log("[evidence] A returned Guardian-quorum VAA proves Wormhole observation/signing only; it is not DOGE TSS signing, custody authorization, transaction broadcast, or release.");
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
        console.log(`[verify:solana] six executable programs; doge-bridge SHA-256 ${localHash}`);
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

    async ensureBridgeCli(): Promise<string> {
        const cli = path.join(this.options.bridgeRepo, "target/debug/doge-bridge-cli");
        if (!firstExecutable([cli])) {
            if (this.options.noBuild) fail(`Missing bridge CLI and --no-build was set: ${cli}`);
            await this.run(["cargo", "build", "-p", "doge-bridge-cli"], "build-bridge-cli", this.options.bridgeRepo);
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
        if (!(await this.accountExists(BRIDGE_STATE_PDA))) {
            await this.run([
                cli, "--rpc-url", SOLANA_RPC_URL,
                "initialize-from-doge-data",
                "--config", dogeConfig,
                "--keys-dir", keysDir,
                "--output", output,
                "--airdrop",
                "--yes",
            ], "initialize-bridge", this.options.bridgeRepo);
        } else {
            console.log(`[reuse:bridge] Bridge state ${BRIDGE_STATE_PDA} already exists; initialization skipped.`);
        }
        if (!fs.existsSync(output)) fail(`Bridge is initialized but ${output} is missing; cannot safely infer the mint/users. Restore matching bridge output or reset the validator.`);
        const bridgeOutput = JSON.parse(fs.readFileSync(output, "utf8")) as { doge_mint?: string; bridge_state_pda?: string };
        if (bridgeOutput.bridge_state_pda !== BRIDGE_STATE_PDA || !bridgeOutput.doge_mint) fail(`Invalid or mismatched bridge output: ${output}`);
        if (createUsers) {
            const payer = path.join(keysDir, "payer.json");
            if (!fs.existsSync(payer)) fail(`Missing initialized payer key: ${payer}`);
            for (const name of ["user1", "user2", "user3"]) {
                const userOutput = path.join(usersDir, `${name}.json`);
                if (fs.existsSync(userOutput)) {
                    console.log(`[reuse:user] ${userOutput}`);
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
            fail("--noop-monitor requires an initialized bridge and matching bridge-config/bridge-output.json. Use --initialize or the initialized-noop profile.");
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

    async startLegacyRedis(): Promise<void> {
        const name = `psy-doge-legacy-ibc-${this.runId}`.toLowerCase().replace(/[^a-z0-9_.-]/g, "-");
        console.warn("[legacy-ibc] Starting Redis only. This is an isolated DUMMY/INCOMPATIBLE queue sandbox, not the verified real-SP1 bridge.");
        const result = Bun.spawnSync([
            "docker", "run", "-d", "--rm",
            "--name", name,
            "--label", `psy.doge.launcher.run=${this.runId}`,
            "--publish", `127.0.0.1:${PORTS.legacyRedis}:6379`,
            "redis:7-alpine",
        ], { stdout: "pipe", stderr: "pipe" });
        if (result.exitCode !== 0) fail(`Failed to start legacy Redis container: ${result.stderr.toString()}`);
        const id = result.stdout.toString().trim();
        this.state.containers.push({ role: "legacy-ibc-redis-dummy", id, name });
        this.persist();
        await waitFor("legacy Redis TCP", 30_000, async () => await portOpen(PORTS.legacyRedis));
        console.log(`[ready:legacy-ibc] Redis sandbox ${id.slice(0, 12)} on 127.0.0.1:${PORTS.legacyRedis}; no incompatible workers started.`);
    }

    async start(): Promise<void> {
        if (loadActiveState()) fail(`Launcher state already exists at ${ACTIVE_STATE_PATH}. Run --teardown first; no unrecorded processes will be killed.`);
        const status = await this.preflight();
        if (this.options.dryRun) {
            if (this.options.profile === "wormhole") {
                console.log("[preflight] PASS — official Wormhole repo commit, structure, tools, Kubernetes context, canonical Core/shim IDs, ports, and deployment/VAA commands validated; no services spawned.");
            } else {
                console.log("[preflight] PASS — paths, tools/build prerequisites, artifacts/build plans, ports, and commands validated; no services spawned.");
            }
            return;
        }
        ensureDirectory(this.runDir);
        this.persist();
        if (this.options.profile === "wormhole") {
            await this.buildMissingWormhole();
            await this.startWormhole();
            const owned = this.state.processes.length + this.state.containers.length;
            console.log(`[ready] Profile ${this.options.profile} is operational. Run directory: ${this.runDir}`);
            console.log("[limitations] Guardian quorum VAA observation is evidence of Wormhole signing only; it does not establish DOGE TSS signing, custody authorization, or release.");
            if (owned === 0) {
                removeActiveState();
                console.log("[ready] Every requested service was reused, so this launcher owns nothing and will exit without tearing anything down.");
                return;
            }
            console.log("Press Ctrl+C to stop only launcher-owned processes/container(s).");
            await new Promise<void>(() => {});
            return;
        }
        const binaries = await this.buildMissing(status);
        const c = this.options.components;
        if (c.has("dogecoin")) await this.startDogecoin(binaries.dogeDaemon!, status.dogeRunning);
        if (c.has("electrs")) await this.startElectrs(binaries.electrs!, status.electrsRunning);
        if (c.has("solana")) await this.startSolana(status.solanaRunning);
        if (c.has("initialize")) await this.initializeBridge(c.has("users"));
        if (c.has("noop-monitor")) await this.startNoopMonitor();
        if (c.has("legacy-ibc")) await this.startLegacyRedis();

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
        profile: "real-noop",
        dryRun: false,
        noBuild: true,
        rebuildPrograms: false,
        deploymentSmokeTest: false,
        teardown: true,
        purge,
        components: new Set(),
        projectsDir: DEFAULT_PROJECTS_DIR,
        bridgeRepo: path.join(DEFAULT_PROJECTS_DIR, "psy-doge-solana-bridge"),
        dogecoinRepo: path.join(DEFAULT_PROJECTS_DIR, "dogecoin"),
        electrsRepo: path.join(DEFAULT_PROJECTS_DIR, "electrs-doge"),
        sp1Repo: path.join(DEFAULT_PROJECTS_DIR, "psy-bridge-sp1"),
        wormholeRepo: path.join(DEFAULT_PROJECTS_DIR, "wormhole"),
        dogeRpcUser: "doge",
        dogeRpcPassword: "doge",
    };
    const launcher = new Launcher(dummyOptions);
    launcher.state.runId = state.runId;
    launcher.state.runDir = state.runDir;
    launcher.state.processes = state.processes;
    launcher.state.containers = state.containers;
    launcher.state.wormhole = state.wormhole;
    await launcher.cleanup(purge);
    console.log("[teardown] Complete; only recorded ownership was targeted.");
}

async function main(): Promise<void> {
    const options = resolveOptions();
    if (!options) return;
    if (options.deploymentSmokeTest) {
        runDeploymentSmokeTest();
        return;
    }
    if (options.teardown) {
        await teardown(options.purge);
        return;
    }
    if (options.deploy) {
        const launcher = new Launcher(options);
        await launcher.deployPublic();
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
        await launcher.start();
    } catch (error) {
        if (loadActiveState()?.runId === launcher.runId) await launcher.cleanup(false);
        throw error;
    }
}

main().catch((error) => {
    console.error(`[error] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
});
