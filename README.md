# malljb234-gatekeeper

Proof Gatekeeper agent for **zkVerify Agent Games — Season 01** (21 Oct – 21 Nov 2026).
Track: **Proof Gatekeeper** (100,000 VFY prize pool for the track: 50k / 30k / 20k).
Agent: **malljb234-gatekeeper** · owner `@malljb238` · GitHub `malljb234`.

## What it does

A public HTTPS endpoint. The platform POSTs a signed task envelope describing
a transfer request; the agent has 60 seconds to decide APPROVE or REJECT and
prove the decision with a Groth16 zero-knowledge proof that the platform
re-verifies against its own registered verification key.

1. **Verify the HMAC signature on the raw request body** before parsing
   anything. Bad signature → 401, no further work.
2. **Decide deterministically** — a fixed checklist over the task fields
   (official trap encyclopedia, 7 varieties):
   - `proof_vk` must equal `registered_vk` and the registered key, else
     `VK_SUBSTITUTION`
   - `public_balance >= minimum`, else `THRESHOLD_MISMATCH`
   - `expiry_block > current_block`, else `EXPIRED_CONDITION`
   - `recipient == condition_recipient`, else `RECIPIENT_MISMATCH`
   - `amount <= max_transfer`, else `AMOUNT_OVERFLOW`
   - `proof_tx` not seen before, else `PROOF_REUSED` (rejected with no
     proof — the tournament excludes those from the proof bonus)
   - all checks pass → `VALID_CONDITION` / APPROVE
3. **Generate a Groth16 proof** of that decision with snarkjs 0.7.6 and the
   tournament's own gatekeeper circuit (BN254, Circom 2.x), and return the
   proof + public signals in the HMAC-signed response.
4. **Fail closed.** Any error, timeout, or uncertainty → REJECT.
5. **Remember.** Task IDs and proof references persist in `state.json`, so
   a re-submitted proof is rejected and a retried task returns the
   identical cached response.

Scoring (official): correct APPROVE/REJECT +12, wrong APPROVE −6, wrong
REJECT −3, timeout −2, missing/invalid proof −2, reliability bonus +0…+5.

## Circuit (verified against official sources)

- Circuit files downloaded from the official site:
  `https://agentgames.zkverify.io/circuits/gatekeeper.wasm` (1,755,820 bytes)
  and `gatekeeper_final.zkey` (309,750 bytes).
- Registered verification-key hash, from the official
  `https://agentgames.zkverify.io/api/circuit-info`:
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- `circuits/verification_key.json` was exported from the official zkey with
  `snarkjs zkey export verificationkey` (protocol groth16, curve bn128,
  nPublic 13).
- The circuit's 13 input signals were confirmed by running the official
  wasm+zkey locally (see `probe-circuit.js`):
  `registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer,
  decision, taskId, salt`.

## Run locally

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<secret from the Agent Games dashboard> node server.js
# GET  /health  -> {"status":"ok", ...}
# POST /  or  POST /task  (HMAC-signed task envelope)
```

The HMAC secret is the per-agent secret from the Agent Games dashboard
("Rotate Secret"). **Never commit it.** Without it the server answers
`/health` only and returns 503 for tasks.

## Tests

```bash
node probe-circuit.js   # circuit truth: valid approve proves; trap approves
                        # and wrong rejects fail to prove; trap rejects prove
node test/test-local.js # end-to-end HTTP: approve, trap, reuse, replay,
                        # bad HMAC (401), unsigned (401), no secret (503)
node test/test-vercel.js # same cases through the Vercel handler (api/index.js)
                        # + cold-start / first-proof latency measurement
node test/test-netlify.js # same cases through the Netlify handler
                        # (netlify/functions/gatekeeper.js) + GET / and
                        # base64-body cases + cold-start latency
```

## Deploy (Netlify — current attempt, free, no card)

The agent runs as a serverless function
(`netlify/functions/gatekeeper.js`, same `lib/gatekeeper.js` core as
`server.js`, so behaviour is identical). Register
**`https://<site>.netlify.app/.netlify/functions/gatekeeper`** as the
agent endpoint (netlify.toml also rewrites `/`, `/health`, `/task` and
`/api` to the function, so the site root answers health too).

1. Sign up at netlify.com with GitHub (Free plan: $0, no card) and
   import this repo.
2. No build settings to change: `netlify.toml` sets the functions
   directory, bundles `circuits/**` with the function via
   `included_files`, and `npm install` runs automatically.
3. Add environment variable `AGENT_GAMES_HMAC_SECRET` = the secret from
   the Agent Games dashboard. (Do **not** put it in the repo.)
4. Deploy, open
   `https://<site>.netlify.app/.netlify/functions/gatekeeper` in a
   browser — it should answer `{"status":"ok", ...}` — and register
   that URL as the agent endpoint at
   https://agentgames.zkverify.io/dashboard/agents (Proof Gatekeeper).
5. Keep the function warm during rounds: ping the endpoint every few
   minutes during 17:30–03:30 WIB (a cold start costs a few seconds;
   first proof ~0.9s locally; well inside the 60s window, and inside
   Netlify's 10s free-plan function limit).
6. In the Agent Games dashboard, run the signed preflight and at least
   one practice task before the next scored round.

Netlify caveats: functions are stateless — `state.json` lives in `/tmp`
and in memory, so a cold start can forget a seen `proof_tx` (same
trade-off as Vercel). Free plan = 300 credits/month, hard cap, no
overage billing — our usage (a few deploys + hundreds of ~2s
invocations) is a few credits. **If Netlify asks for phone verification
or a credit card at signup, STOP — do not enter the phone number or a
card.**

## Deploy (Vercel Hobby — BLOCKED 12h, phone verification)

Vercel was the first serverless choice, but on 15 Nov 2026 ~11:17 WIB
signup hit SMS phone verification that failed (session expired, "Too
many requests") and the number is now temporarily blocked for 12 hours
(until ~23:17 WIB). Do **not** retry the phone step until the block
lifts, and do not re-click Continue repeatedly. A reminder is set for
23:20 WIB to retry once, carefully. The Vercel code path
(`api/index.js`) still works and is tested (15/15); only the account
step is blocked.

The agent runs as a serverless function (`api/index.js`, same
`lib/gatekeeper.js` core as `server.js`, so behaviour is identical).
Register **`https://<project>.vercel.app/api`** as the agent endpoint.

1. Sign up at vercel.com with GitHub (Hobby plan: $0, no card) and import
   this repo.
2. No build settings to change: `npm install` runs automatically, the
   function is `api/index.js`, `vercel.json` sets `maxDuration: 60`.
3. Add environment variable `AGENT_GAMES_HMAC_SECRET` = the secret from
   the Agent Games dashboard. (Do **not** put it in the repo.)
4. Deploy, open `https://<project>.vercel.app/api` in a browser — it
   should answer `{"status":"ok", ...}` — and register that URL as the
   agent endpoint at https://agentgames.zkverify.io/dashboard/agents
   (Proof Gatekeeper).
5. Keep the function warm during rounds: a cold start costs a few seconds
   (first proof ~0.9s locally; well inside the 60s window), but pinging
   `https://<project>.vercel.app/api` every few minutes during
   17:30–03:30 WIB avoids cold starts entirely.
6. In the Agent Games dashboard, run the signed preflight and at least one
   practice task before the next scored round.

Vercel caveat: functions are stateless — `state.json` (seen proof refs +
task cache) lives in `/tmp` and in memory, so a cold start can forget a
seen `proof_tx`. The fail-closed checklist still decides correctly; only
the PROOF_REUSED trap and byte-identical replay depend on remembered
state. This is the price of the no-card free tier; a long-running host
(Render) would keep state, but Render now demands a credit card (below).

## Deploy (Render free tier — BLOCKED, needs a card)

Render was the first choice, but since Nov 2026 new accounts hit an
"Add Card" dialog (temporary $1 authorization) even on the Free plan,
with no way to deploy without a card. Do **not** add a card for this.
If a card is ever added, the steps are: connect this repo → New → Web
Service → Runtime Node → Build `npm install` → Start `node server.js`
→ Free plan → set `AGENT_GAMES_HMAC_SECRET` → deploy → register the
`https://<name>.onrender.com` URL. `render.yaml` holds the same config.

## Event schedule (official)

8 daily scored rounds, 13–21 Nov 2026, 4:00 PM–2:00 AM IST
(= 17:30–03:30 WIB), 8 tasks per agent per round. Rounds 1–2 (13–14 Nov)
already ran; rounds 3–8 run 15–20 Nov. Registration closes 21 Nov 2026.

## License

MIT — see `LICENSE`.
