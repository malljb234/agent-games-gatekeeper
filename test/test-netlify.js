// Test for the Netlify serverless handler (netlify/functions/gatekeeper.js)
// — same cases as test-local.js / test-vercel.js, but through the exact
// code path Netlify will run, with mock Lambda events. Also measures
// cold-start + first-proof latency, which is what decides whether the
// Free-plan 10s function timeout is a risk.
"use strict";

process.env.AGENT_GAMES_HMAC_SECRET = "test-secret-do-not-use-in-production";
process.env.STATE_PATH = "/tmp/gatekeeper-test-netlify-state.json";
try { require("fs").unlinkSync(process.env.STATE_PATH); } catch {}

const crypto = require("crypto");
const path = require("path");
const snarkjs = require("snarkjs");

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const VK = require(path.join(__dirname, "..", "circuits", "verification_key.json"));
const ADDR = "0xDe42000000000000000000000000000000009f01";
const OTHER = "0x1111111111111111111111111111111111111111";

let pass = 0, fail = 0;
function assert(label, cond, extra = "") {
  if (cond) { pass++; console.log(`  PASS ${label}`); }
  else { fail++; console.log(`  FAIL ${label} ${extra}`); }
}

function mockEvent({ method, path: p, headers, body, isBase64Encoded }) {
  return {
    httpMethod: method,
    path: p,
    headers: headers || {},
    body: body === undefined ? null : body,
    isBase64Encoded: !!isBase64Encoded,
    rawUrl: `https://example.netlify.app${p}`,
  };
}
async function call(handler, opts) {
  const t0 = Date.now();
  const res = await handler(mockEvent(opts), {});
  return { ...res, ms: Date.now() - t0 };
}
function validInput(overrides = {}) {
  return {
    registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
    ...overrides,
  };
}
function envelope(taskId, input) {
  return { type: "agent-games.proof-gatekeeper.v1", task_id: taskId, mode: "competition", input };
}
function signedPost(taskId, input, secret = SECRET) {
  const raw = JSON.stringify(envelope(taskId, input));
  const sig = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  return {
    method: "POST",
    path: "/.netlify/functions/gatekeeper",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  };
}

(async () => {
  // Cold start: time the require (snarkjs + circuit paths resolve at load).
  const tCold0 = Date.now();
  const { handler } = require("../netlify/functions/gatekeeper.js");
  const coldMs = Date.now() - tCold0;
  console.log(`== cold require: ${coldMs}ms ==`);

  console.log("== GET /.netlify/functions/gatekeeper -> health ==");
  let r = await call(handler, { method: "GET", path: "/.netlify/functions/gatekeeper", headers: {} });
  let body = JSON.parse(r.body);
  assert("GET health 200 + ok", r.statusCode === 200 && body.status === "ok", r.body.slice(0, 200));
  assert("GET health hmac configured", body.hmac_configured === true);

  console.log("== GET / (rewritten to the function) -> health ==");
  r = await call(handler, { method: "GET", path: "/", headers: {} });
  body = JSON.parse(r.body);
  assert("GET / health 200 + ok", r.statusCode === 200 && body.status === "ok", r.body.slice(0, 200));

  console.log("== POST valid approve (first proof on this instance) ==");
  r = await call(handler, signedPost("nt_test_valid", validInput()));
  body = JSON.parse(r.body);
  assert("valid approve status 200", r.statusCode === 200, r.body.slice(0, 200));
  assert("valid approve decision", body.decision === "APPROVE", r.body.slice(0, 200));
  assert("valid approve has proof", !!body.proof && Array.isArray(body.public_signals));
  if (body.proof) {
    const ok = await snarkjs.groth16.verify(VK, body.public_signals, body.proof);
    assert("valid approve proof verifies", ok === true);
  }
  console.log(`  (first task on cold instance took ${r.ms}ms incl. proof)`);

  console.log("== POST trap: recipient mismatch -> reject with proof ==");
  r = await call(handler, signedPost("nt_test_recipient", validInput({
    condition_recipient: OTHER,
    proof_tx: "0xc4c3000000000000000000000000000000000000000000000000000000008ff3",
  })));
  body = JSON.parse(r.body);
  assert("recipient trap decision", body.decision === "REJECT", r.body.slice(0, 200));
  assert("recipient trap reason", body.reason_code === "RECIPIENT_MISMATCH");
  assert("recipient trap has proof", !!body.proof);
  if (body.proof) {
    const ok = await snarkjs.groth16.verify(VK, body.public_signals, body.proof);
    assert("recipient trap proof verifies", ok === true);
  }

  console.log("== POST bad HMAC -> 401 ==");
  r = await call(handler, signedPost("nt_test_badsig", validInput(), "wrong-secret"));
  assert("bad HMAC 401", r.statusCode === 401, `status=${r.statusCode}`);

  console.log("== POST unsigned -> 401 ==");
  const raw = JSON.stringify(envelope("nt_test_nosig", validInput()));
  r = await call(handler, {
    method: "POST", path: "/.netlify/functions/gatekeeper",
    headers: { "content-type": "application/json" }, body: raw,
  });
  assert("unsigned 401", r.statusCode === 401, `status=${r.statusCode}`);

  console.log("== POST proof reuse (same proof_tx) -> REJECT, no proof ==");
  r = await call(handler, signedPost("nt_test_reuse", validInput()));
  body = JSON.parse(r.body);
  assert("reuse decision", body.decision === "REJECT", r.body.slice(0, 200));
  assert("reuse reason", body.reason_code === "PROOF_REUSED");
  assert("reuse has no proof", !body.proof);

  console.log("== POST base64-encoded body -> decodes and approves ==");
  const rawB64 = JSON.stringify(envelope("nt_test_b64", validInput({
    proof_tx: "0xd4c4000000000000000000000000000000000000000000000000000000008ff4",
  })));
  const sigB64 = crypto.createHmac("sha256", SECRET).update(rawB64).digest("hex");
  r = await call(handler, {
    method: "POST", path: "/.netlify/functions/gatekeeper",
    headers: { "content-type": "application/json", "x-agent-games-signature": sigB64 },
    body: Buffer.from(rawB64, "utf8").toString("base64"),
    isBase64Encoded: true,
  });
  body = JSON.parse(r.body);
  assert("base64 body status 200", r.statusCode === 200, `status=${r.statusCode} ${r.body.slice(0, 200)}`);
  assert("base64 body decision", body.decision === "APPROVE", r.body.slice(0, 200));

  console.log(`\nRESULT: ${pass} passed, ${fail} failed (cold require ${coldMs}ms)`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("TEST FATAL", e); process.exit(1); });
