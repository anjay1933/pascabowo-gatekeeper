import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { signPayload } from "../src/auth";
import { GatekeeperEngine } from "../src/engine";
import { ProofLedger } from "../src/ledger";
import { GatekeeperProver } from "../src/proving";
import type { Settings } from "../src/settings";
import type { Groth16Proof, TaskEnvelope } from "../src/protocol";

/**
 * End-to-end tests against the real server on an ephemeral port.
 * Every task goes through HTTP with a real HMAC signature, and every
 * proof the agent returns is re-verified locally against the verification
 * key — the tests do not trust the agent's own word for anything.
 */

const TEST_SECRET = "test-secret-for-harness-only";
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const PROJECT_ROOT = path.resolve(__dirname, "..");
const CIRCUITS_DIR = (() => {
  // Works from src/ via tsx (project/test) and from dist/ via node (project/dist/test).
  const candidates = [
    path.resolve(PROJECT_ROOT, "circuits"),
    path.resolve(__dirname, "..", "..", "circuits"),
    path.resolve(process.cwd(), "circuits"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, "gatekeeper.wasm"))) return candidate;
  }
  return candidates[0];
})();

let server: http.Server;
let port: number;
let prover: GatekeeperProver;
let vk: unknown;

let counter = 0;
function uniqueId(prefix: string): string {
  counter += 1;
  return `${prefix}-${Date.now()}-${counter}`;
}

function makeTask(overrides: Partial<TaskEnvelope["input"]> = {}): TaskEnvelope {
  const now = new Date();
  const deadline = new Date(now.getTime() + 50_000);
  const taskId = uniqueId("harness-task");
  // Every task gets its own proof_tx (derived from the task id) so tests
  // never trip the PROOF_REUSED rule on each other by accident.
  const proofTx =
    "0x" + crypto.createHash("sha256").update(`tx:${taskId}`).digest("hex");
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "test",
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
      ...overrides,
    },
  };
}

interface Posted {
  status: number;
  body: string;
  signature: string | null;
  elapsedMs: number;
}

async function postTask(
  task: unknown,
  secret: string | null = TEST_SECRET,
  encoding: "hex" | "base64" | "none" = "hex",
): Promise<Posted> {
  const raw = typeof task === "string" ? task : JSON.stringify(task);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (secret !== null && encoding !== "none") {
    const mac = crypto.createHmac("sha256", secret).update(raw).digest();
    headers["x-agent-games-signature"] =
      encoding === "hex" ? mac.toString("hex") : mac.toString("base64");
  }
  const started = Date.now();
  const res = await fetch(`http://127.0.0.1:${port}/agent`, {
    method: "POST",
    headers,
    body: raw,
  });
  return {
    status: res.status,
    body: await res.text(),
    signature: res.headers.get("x-agent-games-signature"),
    elapsedMs: Date.now() - started,
  };
}

function assertSigned(body: string, signature: string | null): void {
  assert.ok(signature, "response must carry x-agent-games-signature");
  const expected = signPayload(TEST_SECRET, body);
  assert.ok(
    crypto.timingSafeEqual(Buffer.from(signature!, "hex"), Buffer.from(expected, "hex")),
    "response signature must verify",
  );
}

interface ReplyShape {
  decision?: string;
  reason_code?: string;
  proof?: Groth16Proof;
  public_signals?: string[];
  proof_tx?: string;
}

async function assertProofValid(reply: ReplyShape): Promise<void> {
  assert.ok(reply.proof, "reply must carry a proof");
  assert.ok(reply.public_signals, "reply must carry public signals");
  assert.equal(reply.public_signals!.length, 13, "13 public signals expected");
  const ok = await prover.check(vk, reply.public_signals!, reply.proof!);
  assert.equal(ok, true, "proof must verify against the verification key");
}

test.before(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgk-test-"));
  const settings: Settings = {
    hmacSecret: TEST_SECRET,
    kurierApiKey: null,
    kurierApiUrl: "https://api.kurier.xyz/api/v1",
    vkHash: VK_HASH,
    circuitsDir: CIRCUITS_DIR,
    ledgerPath: path.join(tmpDir, "seen.json"),
    kurierBudgetMs: 15_000,
    kurierPollIntervalMs: 3_000,
    softDeadlineMs: 50_000,
    port: 0,
  };
  const engine = new GatekeeperEngine(settings, new ProofLedger(settings.ledgerPath));
  prover = new GatekeeperProver(CIRCUITS_DIR);
  vk = JSON.parse(
    fs.readFileSync(path.join(CIRCUITS_DIR, "verification_key.json"), "utf8"),
  ) as unknown;
  const { buildServer } = await import("../src/server");
  server = buildServer(engine);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object", "server must listen");
  port = address.port;
});

test.after(async () => {
  // fetch() keeps connections alive by default; close() alone waits for
  // them forever, so drop them first, then close the server.
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  // snarkjs/ffjavascript leaves a worker-thread pool alive after the
  // first proof; without this the test process never exits (see
  // GatekeeperProver.shutdown).
  await prover.shutdown();
});

test("health: GET /agent returns the protocol handshake", async () => {
  const res = await fetch(`http://127.0.0.1:${port}/agent`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, protocolVersion: "v1" });
});

test("valid task: APPROVE with a locally verifiable proof, signed, fast", async () => {
  const task = makeTask();
  const posted = await postTask(task);
  assert.equal(posted.status, 200);
  assert.ok(posted.elapsedMs < 60_000, `answered in ${posted.elapsedMs} ms (< 60 s)`);
  assertSigned(posted.body, posted.signature);
  const reply = JSON.parse(posted.body) as ReplyShape;
  assert.equal(reply.decision, "APPROVE");
  assert.equal(reply.reason_code, "VALID_CONDITION");
  await assertProofValid(reply);
  assert.equal(reply.public_signals![11], "1", "decision signal must be 1 for APPROVE");
  assert.equal(reply.proof_tx, task.input.proof_tx, "no Kurier key: proof_tx echoes input");
});

test("HMAC: base64 signature accepted; tampered, wrong-secret and missing rejected", async () => {
  const task = makeTask();
  const base64 = await postTask(task, TEST_SECRET, "base64");
  assert.equal(base64.status, 200, "base64-encoded MAC must be accepted");
  assert.equal((JSON.parse(base64.body) as ReplyShape).decision, "APPROVE");

  // Sign the original body, then send a modified body with that signature.
  const raw = JSON.stringify(task);
  const goodMac = signPayload(TEST_SECRET, raw);
  const res = await fetch(`http://127.0.0.1:${port}/agent`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": goodMac,
    },
    body: raw.replace(task.task_id, `${task.task_id}x`),
  });
  assert.equal(res.status, 401, "body tampered after signing must be rejected");

  const wrongSecret = await postTask(makeTask(), "definitely-not-the-secret");
  assert.equal(wrongSecret.status, 401);
  const missing = await postTask(makeTask(), null, "none");
  assert.equal(missing.status, 401);
});

test("preflight: signed handshake reply; bad HMAC rejected", async () => {
  const envelope = { type: "agent-games.preflight.v1", agent_id: "pascabowo" };
  const posted = await postTask(envelope);
  assert.equal(posted.status, 200);
  assertSigned(posted.body, posted.signature);
  assert.deepEqual(JSON.parse(posted.body), { ok: true, protocolVersion: "v1" });
  const bad = await postTask(envelope, "wrong-secret");
  assert.equal(bad.status, 401);
});

test("traps: all six reject with the right reason code", async () => {
  // Seed the ledger with a known proof_tx for the PROOF_REUSED case.
  const seedTx = "0x" + "11".repeat(32);
  const seed = makeTask({ proof_tx: seedTx });
  const seedReply = await postTask(seed);
  assert.equal((JSON.parse(seedReply.body) as ReplyShape).decision, "APPROVE");

  const cases: Array<{
    name: string;
    overrides: Partial<TaskEnvelope["input"]>;
    reason: string;
    provable: boolean;
  }> = [
    {
      name: "VK_SUBSTITUTION",
      overrides: { proof_vk: "0x" + "22".repeat(32) },
      reason: "VK_SUBSTITUTION",
      provable: true,
    },
    {
      name: "PROOF_REUSED",
      overrides: { proof_tx: seedTx },
      reason: "PROOF_REUSED",
      provable: false,
    },
    {
      name: "THRESHOLD_MISMATCH",
      overrides: { public_balance: "99" },
      reason: "THRESHOLD_MISMATCH",
      provable: true,
    },
    {
      name: "EXPIRED_CONDITION",
      overrides: { current_block: 1000 },
      reason: "EXPIRED_CONDITION",
      provable: true,
    },
    {
      name: "RECIPIENT_MISMATCH",
      overrides: { recipient: "0x2222222222222222222222222222222222222222" },
      reason: "RECIPIENT_MISMATCH",
      provable: true,
    },
    {
      name: "AMOUNT_OVERFLOW",
      overrides: { amount: "101" },
      reason: "AMOUNT_OVERFLOW",
      provable: true,
    },
  ];
  for (const c of cases) {
    const posted = await postTask(makeTask(c.overrides));
    assert.equal(posted.status, 200, c.name);
    assertSigned(posted.body, posted.signature);
    const reply = JSON.parse(posted.body) as ReplyShape;
    assert.equal(reply.decision, "REJECT", c.name);
    assert.equal(reply.reason_code, c.reason, c.name);
    if (c.provable) {
      await assertProofValid(reply);
      assert.equal(reply.public_signals![11], "0", `${c.name}: decision signal must be 0`);
    } else {
      assert.equal(reply.proof, undefined, "PROOF_REUSED must carry no proof");
      assert.equal(reply.public_signals, undefined, "PROOF_REUSED must carry no signals");
      assert.equal(reply.proof_tx, seedTx, "PROOF_REUSED echoes the input proof_tx");
    }
  }
});

test("boundaries: balance == minimum, amount == max, block == expiry - 1 approve", async () => {
  const atEdge = makeTask({ public_balance: "100", amount: "100", current_block: 999 });
  const posted = await postTask(atEdge);
  const reply = JSON.parse(posted.body) as ReplyShape;
  assert.equal(reply.decision, "APPROVE");
  assert.equal(reply.reason_code, "VALID_CONDITION");
  await assertProofValid(reply);
});

test("idempotency: redelivery returns the cached APPROVE, not a reuse reject", async () => {
  const task = makeTask();
  const first = await postTask(task);
  assert.equal((JSON.parse(first.body) as ReplyShape).decision, "APPROVE");
  const second = await postTask(task);
  assert.equal(second.status, 200);
  assert.equal(second.body, first.body, "redelivery must return the identical cached body");
  assert.equal((JSON.parse(second.body) as ReplyShape).decision, "APPROVE");
});

test("malformed input: REJECT/INVALID_TASK, never approve on error", async () => {
  const badNumber = makeTask({ minimum: "not-a-number" });
  const r1 = await postTask(badNumber);
  assert.deepEqual(JSON.parse(r1.body), { decision: "REJECT", reason_code: "INVALID_TASK" });

  const missingInput = { ...makeTask(), input: undefined };
  const r2 = await postTask(missingInput);
  assert.deepEqual(JSON.parse(r2.body), { decision: "REJECT", reason_code: "INVALID_TASK" });

  const unknownType = { type: "agent-games.something-else.v1", task_id: uniqueId("x") };
  const r3 = await postTask(unknownType);
  assert.equal(r3.status, 400);
  assert.deepEqual(JSON.parse(r3.body), { decision: "REJECT", reason_code: "INVALID_TASK" });

  const badJson = await postTask("{not json", TEST_SECRET);
  assert.equal(badJson.status, 400);
  assert.deepEqual(JSON.parse(badJson.body), { decision: "REJECT", reason_code: "INVALID_TASK" });
});

test("deadline: a task past its deadline is rejected", async () => {
  const stale = makeTask();
  stale.deadline_at = new Date(Date.now() - 60_000).toISOString();
  const posted = await postTask(stale);
  assert.deepEqual(JSON.parse(posted.body), { decision: "REJECT", reason_code: "INVALID_TASK" });
});
