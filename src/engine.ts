import { signPayload, verifyPayload } from "./auth";
import { submitProofToKurier } from "./kurier";
import { ProofLedger } from "./ledger";
import { buildWitnessInputs, evaluateTask, parseTaskInput } from "./policy";
import { GatekeeperProver } from "./proving";
import type { Settings } from "./settings";
import {
  PREFLIGHT_ENVELOPE_TYPE,
  PROTOCOL_VERSION,
  TASK_ENVELOPE_TYPE,
  type TaskEnvelope,
  type TaskReply,
} from "./protocol";

/**
 * The request pipeline, framework-agnostic so the same code serves the
 * local server, a serverless function, and the in-process demo/tests.
 *
 * Per task:
 *   1. HMAC over the RAW body vs x-agent-games-signature — before JSON parsing.
 *   2. Preflight (type = agent-games.preflight.v1) -> signed health reply.
 *   3. Task: idempotency cache first, then deadline sanity, deterministic
 *      policy evaluation, local Groth16 proof (except PROOF_REUSED),
 *      optional Kurier submission, signed response.
 *   4. Any error or uncertainty fails closed to REJECT — never approve on
 *      an internal error, a malformed field, or a missed deadline.
 */

export interface EngineReply {
  status: number;
  body: string;
  /** Value for the x-agent-games-signature response header (null = unsigned). */
  signature: string | null;
}

export class GatekeeperEngine {
  private prover: GatekeeperProver;

  constructor(
    private settings: Settings,
    private ledger: ProofLedger,
  ) {
    this.prover = new GatekeeperProver(settings.circuitsDir);
  }

  health(): EngineReply {
    const body = JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION });
    return { status: 200, body, signature: null };
  }

  async handlePost(
    rawBody: Buffer,
    signatureHeader: string | undefined | null,
  ): Promise<EngineReply> {
    const startedAt = Date.now();

    if (!this.settings.hmacSecret) {
      return {
        status: 500,
        body: JSON.stringify({
          error: "server_misconfigured",
          detail: "AGENT_GAMES_HMAC_SECRET not set",
        }),
        signature: null,
      };
    }

    // 1. Authenticate the raw body BEFORE parsing.
    if (!verifyPayload(this.settings.hmacSecret, rawBody, signatureHeader)) {
      return {
        status: 401,
        body: JSON.stringify({ error: "invalid_signature" }),
        signature: null,
      };
    }

    let envelope: Record<string, unknown>;
    try {
      envelope = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
    } catch {
      return this.signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 2. Preflight handshake.
    if (envelope.type === PREFLIGHT_ENVELOPE_TYPE) {
      return this.signed(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    }

    if (envelope.type !== TASK_ENVELOPE_TYPE) {
      return this.signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 3. Task.
    const task = envelope as unknown as TaskEnvelope;
    try {
      return await this.handleTask(task, startedAt);
    } catch (err) {
      // Fail closed: never approve on an internal error.
      console.error("[engine] task handling error:", (err as Error).message);
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
  }

  private async handleTask(
    task: TaskEnvelope,
    startedAt: number,
  ): Promise<EngineReply> {
    // Idempotent redelivery: answer from the cache, never re-evaluate
    // (a redelivery must not be mistaken for proof reuse).
    if (task.task_id) {
      const cached = this.ledger.cachedReply(task.task_id);
      if (cached) return this.signedRaw(200, cached);
    }

    // Deadline sanity (HMAC already authenticates the sender; this is
    // anti-replay hygiene). Unparseable timestamps are logged, not fatal —
    // only a clearly-past deadline or a far-future issue time fails the task.
    const now = Date.now();
    const deadlineMs = parseTimestamp(task.deadline_at);
    const issuedMs = parseTimestamp(task.issued_at);
    if (deadlineMs !== null && now > deadlineMs) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
    if (issuedMs !== null && issuedMs > now + 5 * 60_000) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    const parsed = parseTaskInput(task.input);
    if (!parsed || !task.task_id) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    const evaluation = evaluateTask(parsed, (tx) => this.ledger.hasProofTx(tx));

    const reply: TaskReply = {
      decision: evaluation.decision,
      reason_code: evaluation.reasonCode,
    };

    if (evaluation.provable) {
      const witness = buildWitnessInputs(
        task,
        parsed,
        evaluation.decision,
        this.settings.hmacSecret,
      );
      try {
        const { proof, publicSignals } = await this.prover.generate(witness);
        reply.proof = proof;
        reply.public_signals = publicSignals;

        // zkVerify submission via Kurier, bounded so the answer stays well
        // inside the 60s deadline. Never blocks the answer on finalization:
        // on budget expiry we still return the proof + public signals.
        const remaining =
          this.settings.softDeadlineMs - (Date.now() - startedAt);
        const budget = Math.min(
          this.settings.kurierBudgetMs,
          Math.max(0, remaining),
        );
        const kurier = await submitProofToKurier(
          {
            apiKey: this.settings.kurierApiKey,
            apiUrl: this.settings.kurierApiUrl,
            vkHash: this.settings.vkHash,
            pollIntervalMs: this.settings.kurierPollIntervalMs,
          },
          proof,
          publicSignals,
          budget,
        );
        reply.proof_tx = kurier?.txHash ? kurier.txHash : parsed.proofTx;
      } catch (err) {
        // Proving failed: fail closed. An APPROVE without a valid proof is
        // the worst outcome, so downgrade to REJECT with no proof attached.
        console.error("[engine] proof generation failed:", (err as Error).message);
        return this.signed(200, {
          decision: "REJECT",
          reason_code:
            evaluation.decision === "APPROVE"
              ? "INVALID_TASK"
              : evaluation.reasonCode,
          proof_tx: parsed.proofTx,
        });
      }
    } else {
      // PROOF_REUSED: documented as having no proof to submit; echo the
      // reference instead.
      reply.proof_tx = parsed.proofTx;
    }

    const result = this.signed(200, reply);
    // Record only after a successful evaluation, so a task never flags itself.
    this.ledger.noteProofTx(parsed.proofTx);
    this.ledger.cacheReply(task.task_id, result.body);
    return result;
  }

  private signed(status: number, obj: unknown): EngineReply {
    return this.signedRaw(status, JSON.stringify(obj));
  }

  private signedRaw(status: number, body: string): EngineReply {
    return { status, body, signature: signPayload(this.settings.hmacSecret, body) };
  }
}

/** Tolerant timestamp parse: ISO string, epoch seconds, or epoch ms. */
export function parseTimestamp(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value < 1e12 ? value * 1000 : value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    const asNum = Number(trimmed);
    if (/^[0-9]+$/.test(trimmed) && Number.isFinite(asNum)) {
      return asNum < 1e12 ? asNum * 1000 : asNum;
    }
    const parsed = Date.parse(trimmed);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}
