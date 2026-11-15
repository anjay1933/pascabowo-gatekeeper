import * as fs from "fs";
import * as http from "http";
import * as path from "path";
import { GatekeeperEngine } from "./engine";
import { ProofLedger } from "./ledger";
import { SIGNATURE_HEADER } from "./protocol";
import { loadSettings, type Settings } from "./settings";

/**
 * Plain node:http server — no framework, no extra dependencies.
 *
 *   GET  /agent  -> health { ok, protocolVersion } (unsigned)
 *   POST /agent  -> task / preflight handling (HMAC-verified, signed replies)
 *   anything else -> 404
 *
 * The engine is framework-agnostic, so this file is only transport: it
 * reads the raw body (needed for HMAC verification), hands it to the
 * engine, and attaches the x-agent-games-signature response header when
 * the engine signs a reply.
 */

export function buildServer(engine: GatekeeperEngine): http.Server {
  return http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/agent") {
      const reply = engine.health();
      res.writeHead(reply.status, { "content-type": "application/json" });
      res.end(reply.body);
      return;
    }
    if (req.method === "POST" && url.pathname === "/agent") {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const headerValue = req.headers[SIGNATURE_HEADER];
        const signature = Array.isArray(headerValue)
          ? headerValue[0]
          : headerValue;
        void engine
          .handlePost(Buffer.concat(chunks), signature)
          .then((reply) => {
            const headers: Record<string, string> = {
              "content-type": "application/json",
            };
            if (reply.signature) headers[SIGNATURE_HEADER] = reply.signature;
            res.writeHead(reply.status, headers);
            res.end(reply.body);
          })
          .catch((err: Error) => {
            console.error("[server] unhandled error:", err.message);
            res.writeHead(500, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "internal_error" }));
          });
      });
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
}

/**
 * Minimal .env loader for local runs (no dependency): KEY=VALUE lines,
 * ignores blanks and # comments, never overrides an already-set variable.
 * Hosted deployments should use real environment variables instead.
 */
function loadDotEnv(): void {
  const candidates = [
    path.resolve(process.cwd(), ".env"),
    path.resolve(__dirname, "..", ".env"),
  ];
  for (const file of candidates) {
    try {
      const lines = fs.readFileSync(file, "utf8").split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq <= 0) continue;
        const key = trimmed.slice(0, eq).trim();
        const value = trimmed.slice(eq + 1).trim();
        if (key && process.env[key] === undefined) process.env[key] = value;
      }
      return;
    } catch {
      /* no .env here — try the next candidate */
    }
  }
}

export function createEngine(settings: Settings): GatekeeperEngine {
  return new GatekeeperEngine(settings, new ProofLedger(settings.ledgerPath));
}

async function main(): Promise<void> {
  loadDotEnv();
  const settings = loadSettings();
  if (!settings.hmacSecret) {
    console.error(
      "[server] AGENT_GAMES_HMAC_SECRET is not set — POST /agent will answer 500 server_misconfigured.",
    );
  }
  const engine = createEngine(settings);
  const server = buildServer(engine);
  server.listen(settings.port, () => {
    console.log(
      `[server] pascabowo-gatekeeper listening on :${settings.port} (GET /agent for health)`,
    );
    console.log(
      `[server] kurier ${settings.kurierApiKey ? "enabled" : "disabled (no KURIER_API_KEY — proofs stay local)"}`,
    );
  });
}

if (require.main === module) {
  void main();
}
