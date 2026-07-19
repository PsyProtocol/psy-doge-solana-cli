import { describe, expect, test } from "bun:test";
import { Keypair } from "@solana/web3.js";
import {
    processSpecs,
    pubkeyHex,
    requireRemoteUrl,
    type RuntimeInputs,
    type SupervisorOptions,
} from "./start";

function options(recipientAtas: string[]): SupervisorOptions {
    return {
        dryRun: true,
        projectsDir: "/projects",
        stateDir: "/state",
        rpcUrl: "https://api.devnet.solana.com",
        wsUrl: "wss://api.devnet.solana.com",
        electrsUrl: "https://doge-electrs-testnet-demo.qed.me",
        managerUrl: "https://api.testnet.wormholescan.io",
        redisUrl: "rediss://redis.example/0",
        senderListenPort: 3000,
        senderPublicUrl: "http://127.0.0.1:3000",
        senderTokenFile: "/secure/token",
        operatorKeypair: "/secure/operator.json",
        payerKeypair: "/secure/payer.json",
        operatorStore: "/secure/operator.sqlite",
        recipientAtas,
        dogeMint: Keypair.generate().publicKey.toBase58(),
        startHeight: 67_765_388,
        redisSeed: 1_337,
        evidenceDir: "/state/evidence",
        cliBin: "/release/doge-solana-cli",
        ibcBin: "/release/e2e_block_pipeline",
        senderBin: "/release/sender.js",
        genProofBin: "/release/gen-proof",
        blockElf: "/release/block-transition-testnet",
    };
}

const runtime: RuntimeInputs = {
    senderToken: "t".repeat(32),
    operatorSeed: "11".repeat(32),
    redisPassword: "redis-secret",
    payerSeed: "22".repeat(32),
    initialHeader: "33".repeat(320),
    configParams: "44".repeat(48),
    startHeight: 67_765_388,
};

describe("devnet supervisor contract", () => {
    test("encodes recipient ATAs as 32-byte hex for IBC", () => {
        const ata = Keypair.generate().publicKey;
        const plan = processSpecs(options([ata.toBase58()]), runtime);
        expect(plan.ibc.env?.DOGE_RECIPIENT_ATAS).toBe(Buffer.from(ata.toBytes()).toString("hex"));
        expect(plan.ibc.command).toEqual(["/release/e2e_block_pipeline"]);
    });

    test("keeps secrets out of every command line", () => {
        const ata = Keypair.generate().publicKey.toBase58();
        const plan = processSpecs(options([ata]), runtime);
        const argv = [plan.sender, plan.ibc, plan.daemon].flatMap((spec) => spec.command).join(" ");
        expect(argv).not.toContain(runtime.senderToken);
        expect(argv).not.toContain(runtime.operatorSeed);
        expect(argv).not.toContain(runtime.payerSeed);
        expect(plan.sender.env?.API_TOKEN).toBe(runtime.senderToken);
        expect(argv).not.toContain(runtime.redisPassword!);
        expect(plan.ibc.env?.REDIS_URL).toContain("redis-secret");
        expect(plan.ibc.env?.REDIS_URL).toContain("rediss://");
    });

    test("pins devnet daemon Manager and Wormhole identities", () => {
        const ata = Keypair.generate().publicKey.toBase58();
        const command = processSpecs(options([ata]), runtime).daemon.command;
        expect(command).toContain("devnet");
        expect(command).toContain("1");
        expect(command).toContain("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");
        expect(command).toContain("EtZMZM22ViKMo4r5y4Anovs3wKQ2owUmDpjygnMMcdEX");
    });

    test("rejects literal local and private endpoints", () => {
        for (const url of [
            "http://localhost:8899",
            "http://127.0.0.1:8899",
            "http://10.0.0.8:6379",
            "http://172.16.0.8:6379",
            "http://192.168.1.8:6379",
            "http://[::1]:8899",
        ]) {
            expect(() => requireRemoteUrl(url, "endpoint", ["http:"])).toThrow();
        }
        expect(requireRemoteUrl("https://api.devnet.solana.com", "endpoint", ["https:"])).toBe("https://api.devnet.solana.com");
    });

    test("pubkeyHex preserves exact public key bytes", () => {
        const pubkey = Keypair.generate().publicKey;
        expect(pubkeyHex(pubkey.toBase58())).toBe(Buffer.from(pubkey.toBytes()).toString("hex"));
    });
});
