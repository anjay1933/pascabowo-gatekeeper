import * as fs from "fs";
import * as path from "path";

/**
 * Durable record of proof references the agent has already answered.
 *
 * Two jobs, both required by the platform's security checklist:
 *  - remember every proof_tx already used, so a second task carrying the
 *    same reference is rejected as PROOF_REUSED instead of re-proved;
 *  - cache each task_id's serialized response, so an idempotent redelivery
 *    (the platform retries after network failures) is answered from the
 *    cache and never mistaken for reuse.
 *
 * The in-memory maps are authoritative during the process lifetime; a JSON
 * file backs them across restarts. Persistence is best-effort and atomic
 * (write temp file, rename) so a crash cannot leave a half-written file.
 * A missing or corrupt file simply starts empty — storage may fail open,
 * the policy never does.
 */

export interface LedgerFile {
  proofTx?: string[];
  responses?: Record<string, string>;
}

function normalizeRef(tx: string): string {
  return (tx ?? "").trim().toLowerCase();
}

export class ProofLedger {
  private seenRefs = new Set<string>();
  private cachedReplies = new Map<string, string>();

  constructor(private filePath: string) {
    this.load();
  }

  private load(): void {
    try {
      const data = JSON.parse(
        fs.readFileSync(this.filePath, "utf8"),
      ) as LedgerFile;
      for (const tx of data.proofTx ?? []) this.seenRefs.add(normalizeRef(tx));
      for (const [taskId, body] of Object.entries(data.responses ?? {})) {
        this.cachedReplies.set(taskId, body);
      }
    } catch {
      /* missing/corrupt file -> start empty */
    }
  }

  private persist(): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenRefs],
          responses: Object.fromEntries(this.cachedReplies),
        }),
      );
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error("[ledger] persist failed:", (err as Error).message);
    }
  }

  hasProofTx(proofTx: string): boolean {
    return this.seenRefs.has(normalizeRef(proofTx));
  }

  noteProofTx(proofTx: string): void {
    const key = normalizeRef(proofTx);
    if (!key) return;
    if (!this.seenRefs.has(key)) {
      this.seenRefs.add(key);
      this.persist();
    }
  }

  cachedReply(taskId: string): string | null {
    return this.cachedReplies.get(taskId) ?? null;
  }

  cacheReply(taskId: string, serializedReply: string): void {
    if (!this.cachedReplies.has(taskId)) {
      this.cachedReplies.set(taskId, serializedReply);
      this.persist();
    }
  }

  get size(): number {
    return this.seenRefs.size;
  }
}
