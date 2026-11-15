import * as crypto from "crypto";

/**
 * Field arithmetic for the BN128 scalar field, plus the two conversions
 * the gatekeeper circuit needs:
 *
 *  - envelope values (hex hashes, decimal amounts, free-form ids) mapped
 *    into field elements;
 *  - a deterministic per-task salt, bound to the platform HMAC secret so
 *    a third party cannot predict it and a redelivery reproduces it.
 *
 * Reduction mod p preserves equality, which is all the circuit checks
 * (a 32-byte hash does not fit the field, so it is reduced, never truncated).
 */

/** BN128 scalar field prime. */
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function reduce(n: bigint): bigint {
  const r = n % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

/**
 * Map any envelope value to a field element, returned as a decimal string.
 * Hex strings and decimal strings parse directly; anything else (e.g. a
 * task id like "gk_8d31_x") is hashed with SHA-256 first, then reduced.
 */
export function fieldOf(value: string | bigint): string {
  let n: bigint;
  if (typeof value === "bigint") {
    n = value;
  } else {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) {
      n = BigInt(s);
    } else if (/^[0-9]+$/.test(s)) {
      n = BigInt(s);
    } else {
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  return reduce(n).toString(10);
}

/**
 * Parse a non-negative integer supplied as a decimal string, a hex string,
 * or a JSON number. Returns null on anything else (floats, negatives,
 * empty strings, other types) — the caller treats that as a malformed task.
 */
export function parseAmount(value: unknown): bigint | null {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  }
  if (typeof value !== "string") return null;
  const s = value.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

/** Normalise a hex-looking value for case-insensitive comparison. */
export function sameHex(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Per-task salt for the circuit's private `salt` input:
 * HMAC-SHA256(secret, "gatekeeper-salt:" + taskId), reduced mod p.
 */
export function deriveTaskSalt(secret: string, taskId: string): bigint {
  const digest = crypto
    .createHmac("sha256", secret)
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return reduce(BigInt("0x" + digest.toString("hex")));
}
