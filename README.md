# pascabowo-gatekeeper

A Proof Gatekeeper agent for the [zkVerify Agent Games](https://agentgames.zkverify.io)
(Wildcard + Creator Track entry, competition 21 Oct – 21 Nov 2026).

It is a small public HTTPS endpoint that receives signed payment tasks,
decides **APPROVE** or **REJECT** deterministically, generates a Groth16
proof of that decision locally with snarkjs, optionally submits the proof
to zkVerify mainnet through Kurier, and returns a signed response — all
well inside the platform's 60-second deadline.

No wallet, no funds, no on-chain signing by this agent. The only secret
it holds is the HMAC key the platform uses to sign tasks.

## What it does

A task asks one question: *should this payment go through?* The agent
checks five conditions, in a fixed order, and proves the answer:

1. **VK substitution** — the proof's verification key must equal the
   registered key, or the payment is rejected.
2. **Proof reuse** — a `proof_tx` that was already answered is rejected,
   so one proof can never pay twice.
3. **Threshold** — the public balance must be at least the minimum.
4. **Expiry** — the condition must not have expired at the current block.
5. **Recipient** — the payment recipient must match the condition's
   recipient.
6. **Amount** — the amount must not exceed the maximum transfer.

If every check passes, the decision is `APPROVE / VALID_CONDITION`.
Otherwise it is `REJECT` with the matching reason code
(`VK_SUBSTITUTION`, `PROOF_REUSED`, `THRESHOLD_MISMATCH`,
`EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`).

Every decision — approve *and* reject (except reuse) — comes with a
real Groth16 proof generated against the official gatekeeper circuit,
so the platform can verify the decision without trusting this server.
A replayed task returns the cached answer instead of being re-judged,
and anything malformed, expired, or internally broken is rejected with
`INVALID_TASK` rather than ever approved by mistake.

## Architecture

Plain Node.js, TypeScript, and **snarkjs as the only runtime dependency**.
No web framework — the server is `node:http`, and every module has one
job:

| Module | Job |
| --- | --- |
| `src/server.ts` | HTTP surface: `GET /agent` health, `POST /agent` intake, raw-body HMAC gate, response signing, `.env` loading |
| `src/engine.ts` | The pipeline: cache lookup → policy evaluation → proving → optional Kurier → signed reply |
| `src/policy.ts` | Task parsing, the six-rule decision table, witness inputs for the circuit |
| `src/fieldmath.ts` | Field conversion: hex/decimal strings → `BigInt mod p`, free-form strings → SHA-256 `mod p`, per-task salt |
| `src/auth.ts` | HMAC-SHA256 sign/verify (hex or base64, optional `sha256=` prefix, timing-safe compare) |
| `src/proving.ts` | snarkjs wrapper: `fullProve` + `verify` against the gatekeeper circuit, plus worker-pool shutdown |
| `src/kurier.ts` | Optional Kurier submission: submit proof, poll job status up to 15 s, take the tx hash when it appears |
| `src/ledger.ts` | Seen store: JSON file with seen `proof_tx` values and a task-id → cached-response map |
| `src/settings.ts` | Environment parsing and defaults |
| `src/protocol.ts` | Shared types and constants |
| `src/demo.ts` | Offline demo CLI (`npm run demo`) |

The flow of a task: the server verifies the HMAC over the **raw** body
before parsing any JSON (a bad signature is a 401, never a 400). The
engine checks the response cache first — an identical redelivery gets
the cached APPROVE instead of being misread as proof reuse — then
evaluates the rules in order, proves the evaluated decision with the
circuit, and only then records the `proof_tx` as seen. If Kurier is
configured, the proof is submitted in the background of the same
request with a hard 15-second budget; the answer is never held hostage
by finalization — if no transaction hash comes back in time, the reply
falls back to the task's own `proof_tx`.

## Running it

```bash
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET
npm run build
npm start              # listens on $PORT (default 8787)
```

For development with auto-reload: `npm run dev`.

### Environment

| Variable | Required | Default |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | — (without it, `POST /agent` answers 500 `server_misconfigured`) |
| `KURIER_API_KEY` | no | — (unset = local proofs only, no submission) |
| `KURIER_API_URL` | no | `https://api.kurier.xyz/api/v1` |
| `GATEKEEPER_VK_HASH` | no | `0x6b79c6…77b0` (official gatekeeper verification-key hash) |
| `PORT` | no | `8787` |
| `TASK_SOFT_DEADLINE_MS` | no | `50000` |

### Circuit artifacts

`circuits/verification_key.json` is committed. The two large artifacts
are **not** committed (see `.gitignore`) — download them from the
official Agent Games site before first run:

```bash
curl -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
```

## Testing

```bash
npm test
```

The harness boots the real server on an ephemeral port and asserts:
HMAC round-trip in hex and base64, tamper / wrong-secret / missing
signature → 401; preflight handshake shape and signing; a valid task →
`APPROVE / VALID_CONDITION` with a proof verified locally against the
verification key (13 public signals, decision signal `"1"`); all six
traps → the correct `REJECT` + reason code, with proofs verified where
one is required (`PROOF_REUSED` carries none); boundary cases
(balance == minimum, amount == max, block == expiry − 1) approve;
idempotent redelivery returns the cached APPROVE; malformed input and
past deadlines → `REJECT / INVALID_TASK`; every response signed; every
task answered well under 60 s.

**Result: 9/9 tests pass, suite exits cleanly in ~7 s.**

## Demo

```bash
npm run demo
```

Builds one valid task and one trapped task locally with a throwaway
secret — no platform secret, no network, no Kurier — generates real
proofs, verifies them, and prints timings:

```
valid task : APPROVE/VALID_CONDITION (HTTP 200, 1227 ms total)
  proof    : present | public signals: 13 | decision signal: 1
  verified : true (local groth16.verify, 86 ms)
proof time : cold 405 ms (first fullProve, incl. WASM load) | warm 324 ms
trap task  : REJECT/VK_SUBSTITUTION (HTTP 200)
  verified : true (REJECT proof, decision signal 0)
```

Measured on this machine (shared 1.5 vCPU): cold proof ~400 ms,
warm proof ~320 ms, full first-request round trip ~1.2–1.5 s
(includes WASM load and worker spin-up). The 60-second budget is never
close to threatened.

## Deployment notes

- **Any Node ≥ 20 host works** (VPS, container, PaaS). The real
  competition needs a **public HTTPS endpoint** — the platform calls
  this server, so it must be reachable from the internet, not
  localhost. Put it behind a reverse proxy (Caddy, nginx) for TLS.
- **Uptime matters.** Gatekeeper rounds are daily; a down endpoint
  scores zero for that round. Run it under a process manager
  (systemd, pm2) with restart-on-failure, and keep the `data/`
  directory persistent — the seen store lives there, and losing it
  would let a reused proof through.
- **Secrets:** the HMAC secret comes from the Agent Games dashboard
  ("Rotate Secret"). Never commit `.env`. Rotate the secret if it is
  ever exposed; the server reads it at startup, so a restart picks up
  the new one.
- **Kurier is optional but recommended for scored rounds:** without a
  key, proofs are generated and returned but never land on-chain. With
  a key, each proof is submitted and the on-chain transaction hash is
  returned as `proof_tx`.
- **No state besides the ledger.** The server is stateless apart from
  `data/seen.json`, so it scales horizontally only if that file is
  shared — for the competition, one instance is the right shape.

## Differences & decisions

An honest list of where this build diverges from the most obvious way
to write such an agent, and why:

- **snarkjs worker-pool shutdown (`proving.ts: shutdown()`).**
  The first `fullProve` spins up a pool of worker threads inside
  ffjavascript and snarkjs never tears it down — a short-lived process
  (tests, demo CLI) hangs forever after the first proof even though
  every proof succeeded. I traced this to `ffjavascript`'s thread
  manager (`buildBn128` caches the curve on `globalThis.curve_bn128`
  and exposes `terminate()`), and added an explicit `shutdown()` that
  the test harness and demo call when they are done. The long-running
  server deliberately does *not* call it — its workers are meant to
  stay warm for the next task, and a later proof rebuilds the curve on
  demand if the pool was ever stopped.
- **No web framework.** Express/Fastify would add a dependency and a
  body-parser that reads the body before the HMAC check. With plain
  `node:http` the raw body is in hand first, so the signature is
  verified before any JSON is parsed — which is the whole point of the
  gate.
- **Cache before evaluation, record after.** The response cache is
  consulted before the rules run (so a redelivered APPROVE is not
  mistaken for proof reuse), and `proof_tx` is recorded only after a
  successful evaluation. Recording before proving would poison the
  ledger with tasks that never produced a valid answer.
- **Kurier never blocks the answer.** Submission runs inside the
  request with a 15-second budget and a soft deadline; if Kurier is
  slow or down, the caller still gets a correct, signed, proven
  answer with the input `proof_tx`. A proof that is never submitted is
  a missed score, not a wrong answer — the two failure modes should
  not be conflated.
- **HMAC accepted as hex or base64.** The spec allows either encoding
  (plus an optional `sha256=` prefix); the verifier normalizes before
  comparing, so a platform-side encoding change cannot lock the agent
  out.
- **Fail-closed everywhere.** Malformed fields, past deadlines,
  proving failures, missing secrets — all reject or 500, never
  approve. A proving failure on an otherwise-valid task downgrades to
  `REJECT / INVALID_TASK` with no proof attached, because a decision
  this agent cannot prove is a decision it should not make.
- **Field conversion is the boring, exact part.** Hex and decimal
  strings reduce `mod p`; free-form strings (task ids, addresses as
  text) go through SHA-256 first. The per-task salt is
  `HMAC(secret, "gatekeeper-salt:" + task_id) mod p` — deterministic
  per task, unguessable without the secret, and the only private input
  to the circuit.
- **WASM/zkey are downloaded, not committed.** They are large,
  platform-issued artifacts; the repo carries only the verification
  key and the download commands, so a fresh clone reproduces the exact
  official circuit instead of trusting a binary I happened to check
  in.

## Not yet verified

- **No Kurier API key yet** — submission and on-chain finalization are
  untested against the live Kurier API; the code path is exercised
  only in "no key, skip gracefully" mode.
- **No platform HMAC secret yet** — the HMAC round-trip is verified
  with a test secret; the real secret arrives when the agent is
  registered on the dashboard.
- **No public deployment yet** — the server has only been run on
  localhost; the HTTPS endpoint, uptime, and the platform's own
  preflight/task calls against it are still to be exercised.
