// Test for the Vercel serverless handler (api/index.js) — same cases as
// test-local.js, but through the exact code path Vercel will run, with a
// mock req/res pair. Also measures cold-start + first-proof latency, which
// is what decides whether the Hobby function timeout is a risk.
"use strict";

process.env.AGENT_GAMES_HMAC_SECRET = "test-secret-do-not-use-in-production";
process.env.STATE_PATH = "/tmp/gatekeeper-test-state.json";
try { require("fs").unlinkSync(process.env.STATE_PATH); } catch {}

const crypto = require("crypto");
const path = require("path");
const { Readable } = require("stream");
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

function mockReq({ method, url, headers, body }) {
  const stream = Readable.from(body ? [Buffer.from(body)] : []);
  stream.method = method;
  stream.url = url;
  stream.headers = headers || {};
  return stream;
}
function mockRes() {
  const res = { statusCode: null, headers: null, body: "", _done: null };
  res.done = new Promise((r) => (res._done = r));
  res.writeHead = (status, headers) => { res.statusCode = status; res.headers = headers; };
  res.end = (body) => { res.body = body || ""; res._done(); };
  return res;
}
async function call(handler, opts) {
  const req = mockReq(opts);
  const res = mockRes();
  const t0 = Date.now();
  await handler(req, res);
  await res.done;
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
    url: "/api",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  };
}

(async () => {
  // Cold start: time the require (snarkjs + wasm paths resolve at load).
  const tCold0 = Date.now();
  const handler = require("../api/index.js");
  const coldMs = Date.now() - tCold0;
  console.log(`== cold require: ${coldMs}ms ==`);

  console.log("== GET /api -> health ==");
  let r = await call(handler, { method: "GET", url: "/api", headers: {} });
  let body = JSON.parse(r.body);
  assert("GET health 200 + ok", r.statusCode === 200 && body.status === "ok", r.body.slice(0, 200));
  assert("GET health hmac configured", body.hmac_configured === true);

  console.log("== POST valid approve (first proof on this instance) ==");
  r = await call(handler, signedPost("vc_test_valid", validInput()));
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
  r = await call(handler, signedPost("vc_test_recipient", validInput({
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
  r = await call(handler, signedPost("vc_test_badsig", validInput(), "wrong-secret"));
  assert("bad HMAC 401", r.statusCode === 401, `status=${r.statusCode}`);

  console.log("== POST unsigned -> 401 ==");
  const raw = JSON.stringify(envelope("vc_test_nosig", validInput()));
  r = await call(handler, {
    method: "POST", url: "/api",
    headers: { "content-type": "application/json" }, body: raw,
  });
  assert("unsigned 401", r.statusCode === 401, `status=${r.statusCode}`);

  console.log("== POST proof reuse (same proof_tx) -> REJECT, no proof ==");
  r = await call(handler, signedPost("vc_test_reuse", validInput()));
  body = JSON.parse(r.body);
  assert("reuse decision", body.decision === "REJECT", r.body.slice(0, 200));
  assert("reuse reason", body.reason_code === "PROOF_REUSED");
  assert("reuse has no proof", !body.proof);

  console.log(`\nRESULT: ${pass} passed, ${fail} failed (cold require ${coldMs}ms)`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("TEST FATAL", e); process.exit(1); });
