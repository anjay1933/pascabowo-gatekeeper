import * as fs from "fs";
import * as path from "path";
import { DEFAULT_KURIER_URL, DEFAULT_VK_HASH } from "./protocol";

/**
 * Runtime settings, all from environment variables.
 * No secret has a default value: the HMAC secret must come from the
 * platform dashboard ("Rotate Secret") via AGENT_GAMES_HMAC_SECRET.
 * Everything else has a sane default and can be overridden for local runs.
 */
export interface Settings {
  hmacSecret: string;
  kurierApiKey: string | null;
  kurierApiUrl: string;
  /** Registered gatekeeper vk_hash on zkVerify mainnet. */
  vkHash: string;
  circuitsDir: string;
  ledgerPath: string;
  /** Stop polling Kurier after this long; answers must stay under 60s. */
  kurierBudgetMs: number;
  kurierPollIntervalMs: number;
  /** Soft internal deadline for the whole task pipeline. */
  softDeadlineMs: number;
  port: number;
}

function resolveCircuitsDir(): string {
  // <project>/circuits, resolved for both src/ (tsx) and dist/ layouts.
  const candidates = [
    path.resolve(__dirname, "..", "circuits"),
    path.resolve(__dirname, "..", "..", "circuits"),
    path.resolve(process.cwd(), "circuits"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, "gatekeeper.wasm"))) return candidate;
  }
  return candidates[0];
}

function resolveLedgerPath(): string {
  if (process.env.VERCEL) return "/tmp/pascabowo-gatekeeper-ledger.json";
  return path.resolve(process.cwd(), "data", "seen.json");
}

function num(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function loadSettings(env: NodeJS.ProcessEnv = process.env): Settings {
  return {
    hmacSecret: env.AGENT_GAMES_HMAC_SECRET ?? "",
    kurierApiKey: env.KURIER_API_KEY ? env.KURIER_API_KEY : null,
    kurierApiUrl: env.KURIER_API_URL ?? DEFAULT_KURIER_URL,
    vkHash: env.GATEKEEPER_VK_HASH ?? DEFAULT_VK_HASH,
    circuitsDir: env.CIRCUITS_DIR ?? resolveCircuitsDir(),
    ledgerPath: env.LEDGER_PATH ?? resolveLedgerPath(),
    kurierBudgetMs: num(env, "KURIER_POLL_BUDGET_MS", 15_000),
    kurierPollIntervalMs: num(env, "KURIER_POLL_INTERVAL_MS", 3_000),
    softDeadlineMs: num(env, "TASK_SOFT_DEADLINE_MS", 50_000),
    port: num(env, "PORT", 8787),
  };
}
