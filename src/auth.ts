import * as crypto from "crypto";

/**
 * HMAC-SHA256 signing for the x-agent-games-signature header.
 *
 * The platform computes the MAC over the RAW request body and expects the
 * agent to verify it before parsing any JSON. Outbound, this agent signs
 * with a lowercase hex digest. Inbound, the same MAC bytes are accepted as
 * hex or base64, with an optional "sha256=" prefix — accepting both
 * encodings of the identical MAC is a representation tolerance, not a
 * weakening: the caller must still know the secret.
 */

export function signPayload(secret: string, body: string | Buffer): string {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function decodeMac(candidate: string): Buffer | null {
  let v = candidate.trim();
  if (v.toLowerCase().startsWith("sha256=")) {
    v = v.slice("sha256=".length).trim();
  }
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const decoded = Buffer.from(v, "base64");
    if (decoded.length === 32) return decoded;
  } catch {
    /* not valid base64 — fall through to null */
  }
  return null;
}

export function verifyPayload(
  secret: string,
  body: string | Buffer,
  header: string | undefined | null,
): boolean {
  if (!secret || !header) return false;
  const candidate = decodeMac(header);
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", secret).update(body).digest();
  return (
    candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected)
  );
}
