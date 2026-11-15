import * as fs from "fs";
import * as path from "path";
import { signPayload } from "./auth";
import { GatekeeperEngine } from "./engine";
import { ProofLedger } from "./ledger";
import { buildWitnessInputs, parseTaskInput } from "./policy";
import { GatekeeperProver } from "./proving";
import type { Settings } from "./settings";
import type { Groth16Proof, TaskEnvelope } from "./protocol";

/**
 * Offline demo: builds one valid task envelope locally, runs it through
 * the real engine with a throwaway test secret (no platform secret, no
 * network, no Kurier key), generates a real Groth16 proof, verifies it
 * locally against the verification key, and prints timings + a summary.
 *
 * Also runs one trapped task (VK_SUBSTITUTION) to show a provable REJECT.
 * Nothing here touches the Agent Games platform.
 */

const DEMO_SECRET = "demo-throwaway-secret-do-not-use-in-production";
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function validTask(taskId: string, proofTx: string): TaskEnvelope {
  const now = new Date();
  const deadline = new Date(now.getTime() + 50_000);
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "demo",
    issued_at: now.toISOString(),
    deadline_at: deadline.toISOString(),
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: "100",
      public_balance: "250",
      expiry_block: 1000,
      current_block: 900,
      recipient: "0x1111111111111111111111111111111111111111",
      condition_recipient: "0x1111111111111111111111111111111111111111",
      amount: "50",
      max_transfer: "100",
      proof_tx: proofTx,
    },
  };
}

async function runDemo(): Promise<void> {
  const circuitsDir = path.resolve(__dirname, "..", "circuits");
  const settings: Settings = {
    hmacSecret: DEMO_SECRET,
    kurierApiKey: null,
    kurierApiUrl: "https://api.kurier.xyz/api/v1",
    vkHash: VK_HASH,
    circuitsDir,
    ledgerPath: path.resolve(__dirname, "..", "data", "demo-seen.json"),
    kurierBudgetMs: 15_000,
    kurierPollIntervalMs: 3_000,
    softDeadlineMs: 50_000,
    port: 8787,
  };
  // Fresh ledger each demo run so the proof_tx is never "reused".
  try {
    fs.unlinkSync(settings.ledgerPath);
  } catch {
    /* no previous demo ledger */
  }
  const engine = new GatekeeperEngine(settings, new ProofLedger(settings.ledgerPath));
  const prover = new GatekeeperProver(circuitsDir);
  const vk = JSON.parse(
    fs.readFileSync(path.join(circuitsDir, "verification_key.json"), "utf8"),
  ) as unknown;

  console.log("pascabowo-gatekeeper demo — offline, throwaway secret, no Kurier");
  console.log("---------------------------------------------------------------");

  // --- 1. Valid task -> APPROVE with a real proof -------------------------
  const task = validTask("demo-valid-001", "0x" + "ab".repeat(32));
  const raw = JSON.stringify(task);
  const t0 = Date.now();
  const reply = await engine.handlePost(
    Buffer.from(raw, "utf8"),
    signPayload(DEMO_SECRET, raw),
  );
  const totalMs = Date.now() - t0;
  const parsed = JSON.parse(reply.body) as {
    decision: string;
    reason_code: string;
    proof?: unknown;
    public_signals?: string[];
    proof_tx?: string;
  };
  console.log(`valid task : ${parsed.decision}/${parsed.reason_code} (HTTP ${reply.status}, ${totalMs} ms total)`);
  console.log(`  proof    : ${parsed.proof ? "present" : "MISSING"} | public signals: ${parsed.public_signals?.length ?? 0} | decision signal: ${parsed.public_signals?.[11] ?? "n/a"}`);
  if (parsed.proof && parsed.public_signals) {
    const t1 = Date.now();
    const ok = await prover.check(vk, parsed.public_signals, parsed.proof as Groth16Proof);
    console.log(`  verified : ${ok} (local groth16.verify, ${Date.now() - t1} ms)`);
  }

  // --- 2. Cold vs warm proving time ---------------------------------------
  const prover2 = new GatekeeperProver(circuitsDir);
  const parsedInput = parseTaskInput(task.input);
  if (parsedInput) {
    const witness = buildWitnessInputs(task, parsedInput, "APPROVE", DEMO_SECRET);
    const cold0 = Date.now();
    await prover2.generate(witness);
    const coldMs = Date.now() - cold0;
    const warm0 = Date.now();
    await prover2.generate(witness);
    const warmMs = Date.now() - warm0;
    console.log(`proof time : cold ${coldMs} ms (first fullProve, incl. WASM load) | warm ${warmMs} ms`);
  }

  // --- 3. Trapped task -> provable REJECT ----------------------------------
  const trapped = validTask("demo-trap-001", "0x" + "cd".repeat(32));
  trapped.input.proof_vk =
    "0x00000000000000000000000000000000000000000000000000000000deadbeef";
  const rawTrap = JSON.stringify(trapped);
  const trapReply = await engine.handlePost(
    Buffer.from(rawTrap, "utf8"),
    signPayload(DEMO_SECRET, rawTrap),
  );
  const trapParsed = JSON.parse(trapReply.body) as {
    decision: string;
    reason_code: string;
    proof?: unknown;
    public_signals?: string[];
  };
  console.log(`trap task  : ${trapParsed.decision}/${trapParsed.reason_code} (HTTP ${trapReply.status})`);
  if (trapParsed.proof && trapParsed.public_signals) {
    const ok = await prover.check(vk, trapParsed.public_signals, trapParsed.proof as Groth16Proof);
    console.log(`  verified : ${ok} (REJECT proof, decision signal ${trapParsed.public_signals[11]})`);
  }
  // Stop snarkjs' proving worker pool so this short-lived CLI exits
  // cleanly instead of hanging (see GatekeeperProver.shutdown).
  await prover.shutdown();
  console.log("demo done.");
}

if (require.main === module) {
  runDemo().catch((err: Error) => {
    console.error("demo failed:", err);
    process.exit(1);
  });
}
