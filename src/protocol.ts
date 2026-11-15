/**
 * Protocol constants and wire shapes for the Agent Games
 * "Proof Gatekeeper" event.
 *
 * Field names on the wire are fixed by the platform (see the Builder Field
 * Guide at agentgames.zkverify.io/build); the types below mirror them
 * verbatim so a payload can be checked against the spec at a glance.
 */

export const TASK_ENVELOPE_TYPE = "agent-games.proof-gatekeeper.v1";
export const PREFLIGHT_ENVELOPE_TYPE = "agent-games.preflight.v1";
export const PROTOCOL_VERSION = "v1";
export const SIGNATURE_HEADER = "x-agent-games-signature";

/** Registered gatekeeper verification-key hash on zkVerify mainnet. */
export const DEFAULT_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export const DEFAULT_KURIER_URL = "https://api.kurier.xyz/api/v1";

/** Reason codes from the trap taxonomy on /events/proof-gatekeeper. */
export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "PROOF_REUSED"
  | "THRESHOLD_MISMATCH"
  | "EXPIRED_CONDITION"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_OVERFLOW"
  /** Envelope-level failure outside the documented taxonomy. */
  | "INVALID_TASK";

export type Verdict = "APPROVE" | "REJECT";

/** The `input` object of a task envelope, exactly as the platform sends it. */
export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string | number;
  public_balance: string | number;
  expiry_block: string | number;
  current_block: string | number;
  recipient: string;
  condition_recipient: string;
  amount: string | number;
  max_transfer: string | number;
  proof_tx: string;
}

export interface TaskEnvelope {
  type: typeof TASK_ENVELOPE_TYPE;
  task_id: string;
  mode?: string;
  issued_at?: string | number;
  deadline_at?: string | number;
  input: GatekeeperInput;
}

export interface PreflightEnvelope {
  type: typeof PREFLIGHT_ENVELOPE_TYPE;
  agent_id?: string;
  issued_at?: string | number;
  nonce?: string;
}

/** snarkjs Groth16 proof object (bn128 curve). */
export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface TaskReply {
  decision: Verdict;
  reason_code: ReasonCode;
  proof?: Groth16Proof;
  public_signals?: string[];
  proof_tx?: string;
}

export interface HealthReply {
  ok: true;
  protocolVersion: typeof PROTOCOL_VERSION;
}
