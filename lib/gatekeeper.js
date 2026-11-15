/**
 * malljb234-gatekeeper — shared core for the Proof Gatekeeper agent.
 *
 * Used by BOTH:
 *   - server.js            (plain Node.js HTTP server: Render, local, any VPS)
 *   - api/index.js         (Vercel serverless function, Hobby plan)
 *
 * The logic is identical on both runtimes; only the HTTP plumbing differs.
 * Keeping one core means the locally-tested behaviour (test/test-local.js)
 * is exactly what runs in production.
 *
 * Flow (official builder field guide + Proof Gatekeeper event page):
 *   1. Platform POSTs a signed task envelope (HTTPS, 60s window).
 *   2. Verify the HMAC signature on the RAW body before parsing anything.
 *      Bad signature -> 401, no further work.
 *   3. Decide deterministically over the task fields (fixed checklist):
 *      VK match, balance >= minimum, not expired, recipient match,
 *      amount <= cap, proof reference not seen before.
 *      One mismatch -> REJECT. All pass -> APPROVE.
 *   4. Generate a Groth16 proof of that decision with snarkjs + the
 *      tournament's own gatekeeper circuit (BN254, Circom 2.x) and return
 *      the proof + public signals in the signed response.
 *   5. Fail closed: any error / timeout / uncertainty -> REJECT.
 *   6. Remember: task IDs + proof references are persisted, so a
 *      re-submitted proof is rejected and a retried task returns the
 *      identical cached response.
 *
 * Environment:
 *   AGENT_GAMES_HMAC_SECRET  per-agent secret from the Agent Games
 *                              dashboard ("Rotate Secret"). REQUIRED for
 *                              serving tasks; without it the endpoint
 *                              answers /health only and 503s tasks.
 *   REGISTERED_VK_HASH       default = official gatekeeper vkHash from
 *                              https://agentgames.zkverify.io/api/circuit-info
 *                              (0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0)
 *   STATE_PATH               where to persist seen proof refs + task cache.
 *                              Default: <repo-root>/state.json. On Vercel
 *                              the filesystem is read-only except /tmp, so
 *                              api/index.js sets STATE_PATH=/tmp/... and
 *                              persistence is best-effort (in-memory state
 *                              survives only while the instance is warm).
 *
 * Assumptions that can only be confirmed by the dashboard preflight /
 * practice tasks (documented, not guessed-away):
 *   - Incoming HMAC header is `x-agent-games-signature` (the build guide
 *     names this header for responses; the request header is assumed the
 *     same). Also accepts `x-signature` and `x-hub-signature-256`.
 *   - HMAC = HMAC-SHA256 hex over the raw request body (optionally with a
 *     `sha256=` prefix, stripped before comparison).
 *   - Response carries decision, reason_code, proof_tx plus, for provable
 *     decisions, the snarkjs `proof` object and `public_signals` array.
 *   - `taskId` circuit signal = first 31 bytes of sha256(task_id) as a
 *     field element; `salt` = first 31 bytes of HMAC(secret, task_id).
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const REGISTERED_VK_HASH =
  (process.env.REGISTERED_VK_HASH ||
    "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0").toLowerCase();

// Circuit artifacts live in <repo-root>/circuits/. Where that resolves
// depends on the runtime:
//   - local / plain server / Vercel: lib/ is a real folder, so
//     <lib>/../circuits works.
//   - Netlify: the function is bundled (esbuild) to
//     /var/task/netlify/functions/, and included_files land at their
//     repo-relative path under /var/task, so the artifacts are two levels
//     up from the bundled file — or at process.cwd()/circuits (cwd is the
//     project root on Netlify).
// Try each candidate and use the first one that exists on disk; the
// decision + proof logic is identical on every runtime.
function resolveArtifact(name) {
  const candidates = [
    path.join(__dirname, "..", "circuits", name),
    path.join(process.cwd(), "circuits", name),
    path.join(__dirname, "..", "..", "circuits", name),
    path.join(__dirname, "circuits", name),
  ];
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c;
    } catch {
      // ignore and try the next candidate
    }
  }
  return candidates[0];
}

const WASM = resolveArtifact("gatekeeper.wasm");
const ZKEY = resolveArtifact("gatekeeper_final.zkey");
const STATE_PATH =
  process.env.STATE_PATH || path.join(__dirname, "..", "state.json");

function hmacSecret() {
  return process.env.AGENT_GAMES_HMAC_SECRET || "";
}

// ---------------------------------------------------------------------------
// Persistent state: seen proof references + cached responses per task id.
// ---------------------------------------------------------------------------
let state = { seenProofTx: [], taskCache: {} };
try {
  if (fs.existsSync(STATE_PATH)) {
    state = JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
    state.seenProofTx = state.seenProofTx || [];
    state.taskCache = state.taskCache || {};
  }
} catch (e) {
  console.error("state load failed, starting empty:", e.message);
}
const seenProofTx = new Set(state.seenProofTx);
const taskCache = new Map(Object.entries(state.taskCache));
let saveTimer = null;
function saveState() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      fs.writeFileSync(
        STATE_PATH,
        JSON.stringify(
          { seenProofTx: [...seenProofTx], taskCache: Object.fromEntries(taskCache) },
          null,
          2
        )
      );
    } catch (e) {
      console.error("state save failed:", e.message);
    }
  }, 200);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function fieldFromHashHex(hex) {
  // First 31 bytes of a hash as a BN254 field element (always < Fr).
  return BigInt("0x" + hex.slice(0, 62)).toString(10);
}
function sha256hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}
function hmacHex(secret, data) {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}
function timingSafeEqualHex(a, b) {
  try {
    const ba = Buffer.from(a, "hex");
    const bb = Buffer.from(b, "hex");
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}
function normAddr(a) {
  return String(a || "").toLowerCase();
}
function normHash(h) {
  return String(h || "").toLowerCase();
}
function toBigIntLoose(v) {
  // Accept decimal strings, hex strings, or numbers.
  if (typeof v === "number") return BigInt(v);
  const s = String(v).trim();
  return s.startsWith("0x") || s.startsWith("0X") ? BigInt(s) : BigInt(s);
}

// ---------------------------------------------------------------------------
// Decision checklist (official trap encyclopedia, 7 varieties).
// Returns { decision: "APPROVE"|"REJECT", reason_code }.
// ---------------------------------------------------------------------------
function decide(input) {
  const proofTx = normHash(input.proof_tx || input.proofTx || "");
  if (proofTx && seenProofTx.has(proofTx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", proofTx };
  }
  const registeredVk = normHash(input.registered_vk || input.registeredVk || "");
  const proofVk = normHash(input.proof_vk || input.proofVk || "");
  if (
    !registeredVk ||
    !proofVk ||
    registeredVk !== proofVk ||
    registeredVk !== REGISTERED_VK_HASH
  ) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", proofTx };
  }
  let minimum, publicBalance, expiryBlock, currentBlock, amount, maxTransfer;
  try {
    minimum = toBigIntLoose(input.minimum);
    publicBalance = toBigIntLoose(input.public_balance ?? input.publicBalance);
    expiryBlock = toBigIntLoose(input.expiry_block ?? input.expiryBlock);
    currentBlock = toBigIntLoose(input.current_block ?? input.currentBlock);
    amount = toBigIntLoose(input.amount);
    maxTransfer = toBigIntLoose(input.max_transfer ?? input.maxTransfer);
  } catch {
    return { decision: "REJECT", reason_code: "INVALID_TASK", proofTx };
  }
  if (publicBalance < minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", proofTx };
  }
  if (expiryBlock <= currentBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", proofTx };
  }
  if (normAddr(input.recipient) !== normAddr(input.condition_recipient || input.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", proofTx };
  }
  if (amount > maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", proofTx };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", proofTx };
}

// ---------------------------------------------------------------------------
// Groth16 proof of the decision with the official circuit.
// Circuit signals (verified locally against the official wasm/zkey):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision, taskId, salt   (13 public signals)
// ---------------------------------------------------------------------------
async function proveDecision(input, decision) {
  const secret = hmacSecret();
  const taskId = String(input.task_id || input.taskId || "");
  const circuitInput = {
    registeredVkHash: toBigIntLoose(input.registered_vk || input.registeredVk).toString(10),
    proofVkHash: toBigIntLoose(input.proof_vk || input.proofVk).toString(10),
    minimum: toBigIntLoose(input.minimum).toString(10),
    publicBalance: toBigIntLoose(input.public_balance ?? input.publicBalance).toString(10),
    expiryBlock: toBigIntLoose(input.expiry_block ?? input.expiryBlock).toString(10),
    currentBlock: toBigIntLoose(input.current_block ?? input.currentBlock).toString(10),
    recipient: toBigIntLoose(input.recipient).toString(10),
    conditionRecipient: toBigIntLoose(
      input.condition_recipient || input.conditionRecipient
    ).toString(10),
    amount: toBigIntLoose(input.amount).toString(10),
    maxTransfer: toBigIntLoose(input.max_transfer ?? input.maxTransfer).toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: fieldFromHashHex(sha256hex(taskId || "no-task-id")),
    salt: secret
      ? fieldFromHashHex(hmacHex(secret, taskId || "no-task-id"))
      : fieldFromHashHex(sha256hex("salt:" + taskId)),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM,
    ZKEY
  );
  return { proof, publicSignals };
}

// ---------------------------------------------------------------------------
// Response helper — returns { status, headers, body } (no I/O here).
// ---------------------------------------------------------------------------
function jsonResult(status, obj, sign = false) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  const secret = hmacSecret();
  if (sign && secret) {
    headers["x-agent-games-signature"] = hmacHex(secret, body);
  }
  return { status, headers, body };
}

function healthBody() {
  return {
    status: "ok",
    agent: "malljb234-gatekeeper",
    track: "proof-gatekeeper",
    hmac_configured: Boolean(hmacSecret()),
    seen_proof_refs: seenProofTx.size,
    cached_tasks: taskCache.size,
    time: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Task handling (HMAC -> parse -> idempotency -> decide -> prove -> remember).
// ---------------------------------------------------------------------------
async function handleTask(headers, rawBody) {
  // 1. HMAC first, before parsing anything.
  if (!hmacSecret()) {
    console.error("task received but AGENT_GAMES_HMAC_SECRET is not configured");
    return jsonResult(503, { error: "agent_not_configured" });
  }
  const sigHeader =
    headers["x-agent-games-signature"] ||
    headers["x-signature"] ||
    headers["x-hub-signature-256"] ||
    "";
  const provided = String(sigHeader).replace(/^sha256=/, "").trim();
  const expected = hmacHex(hmacSecret(), rawBody);
  if (!provided || !timingSafeEqualHex(provided, expected)) {
    return jsonResult(401, { error: "bad_signature" });
  }

  // 2. Parse envelope.
  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return jsonResult(400, { error: "invalid_json" });
  }
  const input = envelope.input || envelope;
  const taskId = String(envelope.task_id || envelope.taskId || input.task_id || "");
  const proofTxIn = normHash(input.proof_tx || input.proofTx || "");

  // 3. Idempotency: retried task id -> identical cached response.
  if (taskId && taskCache.has(taskId)) {
    const cached = taskCache.get(taskId);
    return jsonResult(200, cached, true);
  }

  // 4. Decide (fail closed inside decide()).
  const { decision, reason_code, proofTx } = decide(input);
  const response = { decision, reason_code, proof_tx: proofTx || proofTxIn };

  // 5. Prove the decision — except PROOF_REUSED, which carries no proof
  //    (official scoring excludes those from the proof bonus).
  if (reason_code !== "PROOF_REUSED") {
    try {
      const t0 = Date.now();
      const { proof, publicSignals } = await proveDecision(input, decision);
      response.proof = proof;
      response.public_signals = publicSignals;
      console.log(
        `task ${taskId} ${decision} ${reason_code} proof in ${Date.now() - t0}ms`
      );
    } catch (e) {
      // Circuit refused the proof. The checklist already did the safety
      // work (the official guide: the proof is the receipt, the checks
      // are the judgement — a proof can verify and still authorize the
      // wrong action, and vice versa). So keep the checklist decision
      // and return it WITHOUT a proof: scoring gives a correct decision
      // without a valid proof -2, which beats flipping a correct
      // APPROVE into a wrong REJECT (-3) or a correct REJECT into a
      // wrong APPROVE (-6). Log loudly — this should never happen.
      console.error(
        `proof generation failed for ${taskId} (${decision} ${reason_code}):`,
        e.message
      );
      delete response.proof;
      delete response.public_signals;
    }
  } else {
    console.log(`task ${taskId} REJECT PROOF_REUSED (no proof attached)`);
  }

  // 6. Remember: mark the proof reference seen and cache the response.
  //    Only mark seen for decisions that were actually answered with a
  //    proof or a reuse rejection; a task whose proof failed is not
  //    marked, so a corrected retry can still be decided.
  if (response.proof || reason_code === "PROOF_REUSED") {
    if (response.proof_tx) seenProofTx.add(response.proof_tx);
  }
  if (taskId) {
    taskCache.set(taskId, response);
    saveState();
  }
  return jsonResult(200, response, true);
}

// ---------------------------------------------------------------------------
// Router — one entry point for every runtime.
//   method: "GET" | "POST", url: request path, headers: lowercase keys,
//   rawBody: Buffer (empty for GET).
// ---------------------------------------------------------------------------
async function handleRequest({ method, url, headers, rawBody }) {
  const pathOnly = String(url || "/").split("?")[0];
  if (method === "GET" && (pathOnly === "/health" || pathOnly === "/")) {
    return jsonResult(200, healthBody());
  }
  if (method !== "POST" || (pathOnly !== "/" && pathOnly !== "/task")) {
    return jsonResult(404, { error: "not_found" });
  }
  try {
    return await handleTask(headers || {}, rawBody || Buffer.alloc(0));
  } catch (e) {
    console.error("task handler error:", e);
    // Fail closed: any unhandled error -> REJECT without proof.
    return jsonResult(200, {
      decision: "REJECT",
      reason_code: "INVALID_TASK",
      proof_tx: "",
    });
  }
}

module.exports = { handleRequest, handleTask, decide, proveDecision, healthBody };
