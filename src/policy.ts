import { deriveTaskSalt, fieldOf, parseAmount, sameHex } from "./fieldmath";
import type {
  GatekeeperInput,
  ReasonCode,
  TaskEnvelope,
  Verdict,
} from "./protocol";

/**
 * Deterministic policy for Proof Gatekeeper. No model involvement: the
 * final call is made here, fail-closed, and the circuit independently
 * enforces the same comparisons on its public inputs — so the off-chain
 * evaluation must mirror the circuit exactly, including the boundary
 * semantics: balance >= minimum passes, amount <= max_transfer passes,
 * current_block < expiry_block passes.
 *
 * The checks are a rule table evaluated in platform order; the first
 * failing rule wins. Rules are written as data rather than a nested
 * if-chain so the order and the taxonomy stay visible in one place.
 */

export interface ParsedTask {
  registeredVk: string;
  proofVk: string;
  minimum: bigint;
  publicBalance: bigint;
  expiryBlock: bigint;
  currentBlock: bigint;
  recipient: string;
  conditionRecipient: string;
  amount: bigint;
  maxTransfer: bigint;
  proofTx: string;
}

export interface Evaluation {
  decision: Verdict;
  reasonCode: ReasonCode;
  /** True when a Groth16 proof must accompany the response. */
  provable: boolean;
}

/** Structural validation + parsing. Returns null on any malformed field. */
export function parseTaskInput(input: GatekeeperInput | undefined): ParsedTask | null {
  if (!input || typeof input !== "object") return null;
  const minimum = parseAmount(input.minimum);
  const publicBalance = parseAmount(input.public_balance);
  const amount = parseAmount(input.amount);
  const maxTransfer = parseAmount(input.max_transfer);
  const expiryBlock = parseAmount(input.expiry_block);
  const currentBlock = parseAmount(input.current_block);
  if (
    minimum === null ||
    publicBalance === null ||
    amount === null ||
    maxTransfer === null ||
    expiryBlock === null ||
    currentBlock === null
  ) {
    return null;
  }
  const textFields: Array<[unknown, string]> = [
    [input.registered_vk, "registered_vk"],
    [input.proof_vk, "proof_vk"],
    [input.recipient, "recipient"],
    [input.condition_recipient, "condition_recipient"],
    [input.proof_tx, "proof_tx"],
  ];
  for (const [value] of textFields) {
    if (typeof value !== "string" || value.trim() === "") return null;
  }
  return {
    registeredVk: input.registered_vk as string,
    proofVk: input.proof_vk as string,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient as string,
    conditionRecipient: input.condition_recipient as string,
    amount,
    maxTransfer,
    proofTx: input.proof_tx as string,
  };
}

interface Rule {
  code: ReasonCode;
  provable: boolean;
  /** True when the task trips this rule (i.e. must be rejected for it). */
  trips: (task: ParsedTask, isSeen: (tx: string) => boolean) => boolean;
}

const RULES: Rule[] = [
  {
    code: "VK_SUBSTITUTION",
    provable: true,
    trips: (t) => !sameHex(t.proofVk, t.registeredVk),
  },
  {
    code: "PROOF_REUSED",
    provable: false, // documented: a reused-proof task has no proof to submit
    trips: (t, isSeen) => isSeen(t.proofTx),
  },
  {
    code: "THRESHOLD_MISMATCH",
    provable: true,
    trips: (t) => t.publicBalance < t.minimum,
  },
  {
    code: "EXPIRED_CONDITION",
    provable: true,
    trips: (t) => t.currentBlock >= t.expiryBlock,
  },
  {
    code: "RECIPIENT_MISMATCH",
    provable: true,
    trips: (t) => !sameHex(t.recipient, t.conditionRecipient),
  },
  {
    code: "AMOUNT_OVERFLOW",
    provable: true,
    trips: (t) => t.amount > t.maxTransfer,
  },
];

export function evaluateTask(
  parsed: ParsedTask,
  isSeen: (proofTx: string) => boolean,
): Evaluation {
  for (const rule of RULES) {
    if (rule.trips(parsed, isSeen)) {
      return { decision: "REJECT", reasonCode: rule.code, provable: rule.provable };
    }
  }
  return { decision: "APPROVE", reasonCode: "VALID_CONDITION", provable: true };
}

/**
 * Circuit witness inputs for gatekeeper.wasm (signal names recovered from
 * the artifact; the public-signal order is fixed by the circuit):
 *   inputs: taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
 *           expiryBlock, currentBlock, recipient, conditionRecipient,
 *           amount, maxTransfer, decision, salt (private)
 *   public signals: [commitment, registeredVkHash, proofVkHash, minimum,
 *           publicBalance, expiryBlock, currentBlock, recipient,
 *           conditionRecipient, amount, maxTransfer, decision, taskId]
 * where commitment = Poseidon(taskId, salt), computed inside the circuit.
 */
export function buildWitnessInputs(
  envelope: TaskEnvelope,
  parsed: ParsedTask,
  decision: Verdict,
  hmacSecret: string,
): Record<string, string> {
  const salt = deriveTaskSalt(hmacSecret, envelope.task_id);
  return {
    taskId: fieldOf(envelope.task_id),
    registeredVkHash: fieldOf(parsed.registeredVk),
    proofVkHash: fieldOf(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: fieldOf(parsed.recipient),
    conditionRecipient: fieldOf(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}
