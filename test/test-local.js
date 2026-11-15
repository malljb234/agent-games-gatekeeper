// End-to-end test for malljb234-gatekeeper.
// Spawns the server with a test HMAC secret and exercises:
//   valid approve (proof verifies), one trap reject (proof verifies),
//   proof reuse (REJECT, no proof), task replay (byte-identical),
//   bad HMAC (401), missing secret (503).
// The full 7-trap circuit matrix lives in probe-circuit.js.
"use strict";

const http = require("http");
const crypto = require("crypto");
const { spawn } = require("child_process");
const path = require("path");
const snarkjs = require("snarkjs");

const SECRET = "test-secret-do-not-use-in-production";
const PORT = 3456;
const BASE = `http://127.0.0.1:${PORT}`;
const VK = require(path.join(__dirname, "..", "circuits", "verification_key.json"));

const ADDR = "0xDe42000000000000000000000000000000009f01";
const OTHER = "0x1111111111111111111111111111111111111111";

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
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  };
}
function post(bodyObj, secret = SECRET, rawOverride) {
  const raw = rawOverride !== undefined ? rawOverride : JSON.stringify(bodyObj);
  const sig = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  return new Promise((resolve, reject) => {
    const req = http.request(
      `${BASE}/task`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": sig,
          "content-length": Buffer.byteLength(raw),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            raw: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.end(raw);
  });
}
function postWithSig(raw, sigValue, extraHeaders = {}) {
  // POST with a caller-computed signature header value (any encoding).
  return new Promise((resolve, reject) => {
    const req = http.request(
      `${BASE}/task`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": sigValue,
          "content-length": Buffer.byteLength(raw),
          ...extraHeaders,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            raw: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.end(raw);
  });
}
function postRaw(raw, headers = {}) {
  // POST with exactly the caller-supplied headers (no signature header
  // unless the caller adds one) — needed for the "signature" header
  // cases, where x-agent-games-signature must be ABSENT or wrong.
  return new Promise((resolve, reject) => {
    const req = http.request(
      `${BASE}/task`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(raw),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            raw: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.end(raw);
  });
}
function hmacFor(algo, key, payload) {
  // Same digest rules as lib/gatekeeper.js (incl. truncated variants).
  if (algo === "sha384-trunc32")
    return crypto.createHmac("sha384", key).update(payload).digest().subarray(0, 32);
  if (algo === "sha512-trunc32")
    return crypto.createHmac("sha512", key).update(payload).digest().subarray(0, 32);
  return crypto.createHmac(algo, key).update(payload).digest();
}
function encodeSig(buf, enc) {
  if (enc === "base64") return buf.toString("base64");
  if (enc === "base64url") return buf.toString("base64url");
  return buf.toString("hex");
}
function get(pathname) {
  return new Promise((resolve, reject) => {
    http.get(`${BASE}${pathname}`, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode, raw: Buffer.concat(chunks).toString("utf8") })
      );
    }).on("error", reject);
  });
}
async function waitHealth(proc, timeoutMs = 30000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await get("/health");
      if (r.status === 200) return;
    } catch {}
    if (Date.now() - t0 > timeoutMs) throw new Error("server did not become healthy");
    await new Promise((r) => setTimeout(r, 500));
  }
}
function checkResponseSignature(r) {
  const sig = r.headers["x-agent-games-signature"];
  if (!sig) return false;
  const expected = crypto.createHmac("sha256", SECRET).update(r.raw).digest("hex");
  return sig === expected;
}
function checkResponseSignatureAlgo(r, algo, key, enc = "hex") {
  // Response must be signed with the SAME hash + encoding that matched
  // the incoming request (round 3: a SHA-384/base64 platform gets a
  // SHA-384/base64 response signature, not SHA-256 hex).
  const sig = r.headers["x-agent-games-signature"];
  if (!sig) return false;
  return sig === encodeSig(hmacFor(algo, key, r.raw), enc);
}

let pass = 0;
let fail = 0;
function assert(label, cond, extra = "") {
  if (cond) {
    pass++;
    console.log(`  PASS ${label}`);
  } else {
    fail++;
    console.log(`  FAIL ${label} ${extra}`);
  }
}

(async () => {
  const server = spawn("node", [path.join(__dirname, "..", "server.js")], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout.on("data", (d) => process.stdout.write("  [server] " + d));
  server.stderr.on("data", (d) => process.stdout.write("  [server:err] " + d));
  try {
    await waitHealth(server);
    console.log("== health ==");
    const h = await get("/health");
    assert("health 200 + ok", h.status === 200 && JSON.parse(h.raw).status === "ok");

    console.log("== valid approve ==");
    let t0 = Date.now();
    let r = await post(envelope("gk_test_valid", validInput()));
    let body = JSON.parse(r.raw);
    assert("valid approve status 200", r.status === 200, r.raw.slice(0, 200));
    assert("valid approve decision", body.decision === "APPROVE", r.raw.slice(0, 200));
    assert("valid approve reason", body.reason_code === "VALID_CONDITION");
    assert("valid approve has proof", !!body.proof && Array.isArray(body.public_signals));
    assert("response is HMAC-signed", checkResponseSignature(r));
    if (body.proof) {
      const ok = await snarkjs.groth16.verify(VK, body.public_signals, body.proof);
      assert("valid approve proof verifies", ok === true);
      console.log(`  (proof round-trip took ${Date.now() - t0}ms)`);
    }

    console.log("== trap: recipient mismatch -> reject with proof ==");
    r = await post(
      envelope(
        "gk_test_recipient",
        validInput({
          condition_recipient: OTHER,
          proof_tx:
            "0xc4c3000000000000000000000000000000000000000000000000000000008ff3",
        })
      )
    );
    body = JSON.parse(r.raw);
    assert("recipient trap decision", body.decision === "REJECT", r.raw.slice(0, 200));
    assert("recipient trap reason", body.reason_code === "RECIPIENT_MISMATCH");
    assert("recipient trap has proof", !!body.proof);
    if (body.proof) {
      const ok = await snarkjs.groth16.verify(VK, body.public_signals, body.proof);
      assert("recipient trap proof verifies", ok === true);
    }

    console.log("== proof reuse: same proof_tx again -> REJECT, no proof ==");
    r = await post(
      envelope("gk_test_reuse", validInput({ proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1" }))
    );
    body = JSON.parse(r.raw);
    assert("reuse decision", body.decision === "REJECT", r.raw.slice(0, 200));
    assert("reuse reason", body.reason_code === "PROOF_REUSED");
    assert("reuse has no proof", !body.proof);

    console.log("== replay: same task_id again -> byte-identical ==");
    const replayInput = validInput({
      proof_tx:
        "0xb4c2000000000000000000000000000000000000000000000000000000008ff2",
    });
    const first = await post(envelope("gk_test_replay", replayInput));
    const firstBody = JSON.parse(first.raw);
    assert("replay first is APPROVE", firstBody.decision === "APPROVE", first.raw.slice(0, 200));
    const second = await post(envelope("gk_test_replay", replayInput));
    assert("replay identical body", first.raw === second.raw);

    console.log("== bad HMAC -> 401 ==");
    r = await post(envelope("gk_test_badsig", validInput()), "wrong-secret");
    assert("bad HMAC 401", r.status === 401, `status=${r.status}`);

    console.log("== unsigned request -> 401 ==");
    const unsigned = await new Promise((resolve, reject) => {
      const raw = JSON.stringify(envelope("gk_test_nosig", validInput()));
      const req = http.request(
        `${BASE}/task`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(raw),
          },
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode }));
        }
      );
      req.on("error", reject);
      req.end(raw);
    });
    assert("unsigned 401", unsigned.status === 401, `status=${unsigned.status}`);

    console.log("== platform signing variants (preflight 401 diagnosis) ==");
    // Base64-encoded signature, raw string key.
    let rawV = JSON.stringify(envelope("gk_test_b64sig", validInput({
      proof_tx: "0xe1c5000000000000000000000000000000000000000000000000000000008ff5",
    })));
    r = await postWithSig(
      rawV,
      crypto.createHmac("sha256", SECRET).update(rawV).digest("base64")
    );
    body = JSON.parse(r.raw);
    assert("base64 sig approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // `sha256=`-prefixed hex signature.
    rawV = JSON.stringify(envelope("gk_test_shaprefix", validInput({
      proof_tx: "0xe2c5000000000000000000000000000000000000000000000000000000008ff5",
    })));
    r = await postWithSig(
      rawV,
      "sha256=" + crypto.createHmac("sha256", SECRET).update(rawV).digest("hex")
    );
    body = JSON.parse(r.raw);
    assert("sha256= prefix approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // Timestamp-mixed payload: HMAC over `timestamp.body`, timestamp sent
    // in x-agent-games-timestamp.
    const ts = String(Math.floor(Date.now() / 1000));
    rawV = JSON.stringify(envelope("gk_test_tspayload", validInput({
      proof_tx: "0xe3c5000000000000000000000000000000000000000000000000000000008ff5",
    })));
    r = await postWithSig(
      rawV,
      crypto
        .createHmac("sha256", SECRET)
        .update(Buffer.concat([Buffer.from(ts), Buffer.from("."), Buffer.from(rawV)]))
        .digest("hex"),
      { "x-agent-games-timestamp": ts }
    );
    body = JSON.parse(r.raw);
    assert("timestamp.body payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    console.log("== round-2 payload constructions (preflight still 401 live) ==");
    // The live preflight (171-byte body, hex sig) failed with BOTH the
    // raw-string and base64-decoded keys against the raw body, so the
    // platform must sign a different construction. Each case below signs
    // one candidate construction with the test secret and must APPROVE.
    function canonicalJson(v) {
      if (v === null || typeof v !== "object") return JSON.stringify(v);
      if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
      return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
    }
    const hmacBuf = (key, payload) => crypto.createHmac("sha256", key).update(payload).digest();
    function variantTx(n) {
      return "0x" + n.toString(16).padStart(2, "0") + "c6" + "0".repeat(56) + "8ff6";
    }

    // 1. canonical JSON: keys sorted recursively, compact. The raw body is
    //    pretty-printed with REVERSED key order, so raw != canonical.
    let envObj = envelope("gk_test_canonjson", validInput({ proof_tx: variantTx(0xf1) }));
    const reversed = {};
    for (const k of Object.keys(envObj).reverse()) reversed[k] = envObj[k];
    rawV = JSON.stringify(reversed, null, 2);
    r = await postWithSig(rawV, hmacBuf(SECRET, canonicalJson(JSON.parse(rawV))).toString("hex"));
    body = JSON.parse(r.raw);
    assert("canonical-json payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));
    assert("canonical-json response is HMAC-signed", checkResponseSignature(r));

    // 2. re-stringified JSON: pretty raw body, signature over the compact
    //    re-serialisation (same key order, no whitespace).
    rawV = JSON.stringify(envelope("gk_test_restring", validInput({ proof_tx: variantTx(0xf2) })), null, 2);
    r = await postWithSig(rawV, hmacBuf(SECRET, JSON.stringify(JSON.parse(rawV))).toString("hex"));
    body = JSON.parse(r.raw);
    assert("restringified-json payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 3. method + path + body (request-line style).
    rawV = JSON.stringify(envelope("gk_test_methodpath", validInput({ proof_tx: variantTx(0xf3) })));
    r = await postWithSig(rawV, hmacBuf(SECRET, "POST\n/.netlify/functions/gatekeeper\n" + rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("method-path-body payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 4. path + body.
    rawV = JSON.stringify(envelope("gk_test_pathbody", validInput({ proof_tx: variantTx(0xf4) })));
    r = await postWithSig(rawV, hmacBuf(SECRET, "/.netlify/functions/gatekeeper" + rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("path+body payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 5. agent-id prefix.
    rawV = JSON.stringify(envelope("gk_test_agentid", validInput({ proof_tx: variantTx(0xf5) })));
    r = await postWithSig(rawV, hmacBuf(SECRET, "malljb234-gatekeeper" + rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("agentid+body payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 6. HMAC over the hex sha256 of the body.
    rawV = JSON.stringify(envelope("gk_test_shahex", validInput({ proof_tx: variantTx(0xf6) })));
    r = await postWithSig(rawV, hmacBuf(SECRET, crypto.createHash("sha256").update(rawV).digest("hex")).toString("hex"));
    body = JSON.parse(r.raw);
    assert("sha256hex-body payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 7. timestamp taken from the envelope BODY (no timestamp header).
    const tsBody = String(Math.floor(Date.now() / 1000));
    const envTs = { ...envelope("gk_test_bodyts", validInput({ proof_tx: variantTx(0xf7) })), timestamp: tsBody };
    rawV = JSON.stringify(envTs);
    r = await postWithSig(rawV, hmacBuf(SECRET, tsBody + "." + rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("body-timestamp payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 8. key = sha256 of the displayed secret string.
    rawV = JSON.stringify(envelope("gk_test_shakey", validInput({ proof_tx: variantTx(0xf8) })));
    r = await postWithSig(rawV, hmacBuf(crypto.createHash("sha256").update(SECRET).digest(), rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("sha256-of-secret key approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 9. Negative control: canonical payload signed with a WRONG key.
    envObj = envelope("gk_test_canonwrong", validInput({ proof_tx: variantTx(0xf9) }));
    rawV = JSON.stringify(envObj, null, 2);
    r = await postWithSig(rawV, hmacBuf("wrong-secret", canonicalJson(JSON.parse(rawV))).toString("hex"));
    assert("canonical payload + wrong key still 401", r.status === 401, `status=${r.status}`);

    console.log("== round-3 variants (live preflight still 401 after round-2 fix) ==");
    // The live preflight (14:47:28 WIB, req eede5c49) is a 171-byte
    // envelope {type, agent_id, issued_at, nonce} with BOTH an
    // x-agent-games-signature AND a separate "signature" header, and a
    // 64-char signature. Round 2 never tried the "signature" header,
    // non-SHA-256 hashes, agent-id-bound keys, or field-only payloads.
    // Each case below signs one round-3 construction with the test
    // secret and must APPROVE.
    const PREFLIGHT_AGENT_ID = "8609c8b4-8440-42f6-889a-021a4d3bf4c2"; // agent_id UUID from the live preflight body (not secret)
    function preflightEnvelope(taskId, input, extra = {}) {
      return {
        type: "agent-games.preflight.v1",
        agent_id: PREFLIGHT_AGENT_ID,
        issued_at: new Date().toISOString(),
        nonce: crypto.randomUUID(),
        task_id: taskId,
        mode: "competition",
        input,
        ...extra,
      };
    }
    function variantTx3(n) {
      return "0x" + n.toString(16).padStart(2, "0") + "c7" + "0".repeat(56) + "8ff7";
    }
    const r3 = (n) => validInput({ proof_tx: variantTx3(n) });

    // 1. Signature carried ONLY in the "signature" header (no
    //    x-agent-games-signature at all).
    rawV = JSON.stringify(preflightEnvelope("gk_test_r3_sighdr", r3(0xe1)));
    r = await postRaw(rawV, {
      signature: hmacFor("sha256", SECRET, rawV).toString("hex"),
    });
    body = JSON.parse(r.raw);
    assert("signature header only approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 2. x-agent-games-signature WRONG but "signature" correct — any
    //    present signature header that verifies must be accepted.
    rawV = JSON.stringify(preflightEnvelope("gk_test_r3_sighdr2", r3(0xe2)));
    r = await postRaw(rawV, {
      "x-agent-games-signature": hmacFor("sha256", "wrong-secret", rawV).toString("hex"),
      signature: hmacFor("sha256", SECRET, rawV).toString("hex"),
    });
    body = JSON.parse(r.raw);
    assert("wrong x-header + correct signature header approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 3. HMAC-SHA-384, base64-encoded (48 bytes -> exactly 64 chars,
    //    matching the live sig_len=64). Response must come back
    //    SHA-384/base64-signed too.
    rawV = JSON.stringify(preflightEnvelope("gk_test_r3_sha384", r3(0xe3)));
    r = await postWithSig(rawV, encodeSig(hmacFor("sha384", SECRET, rawV), "base64"));
    body = JSON.parse(r.raw);
    assert("sha384 + base64 sig approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));
    assert("sha384 response is sha384/base64 signed", checkResponseSignatureAlgo(r, "sha384", SECRET, "base64"));

    // 4. HMAC-SHA-512/256, hex.
    rawV = JSON.stringify(preflightEnvelope("gk_test_r3_sha512256", r3(0xe4)));
    r = await postWithSig(rawV, encodeSig(hmacFor("sha512-256", SECRET, rawV), "hex"));
    body = JSON.parse(r.raw);
    assert("sha512-256 hex sig approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 5. HMAC-SHA-512 truncated to 32 bytes, hex.
    rawV = JSON.stringify(preflightEnvelope("gk_test_r3_sha512trunc", r3(0xe5)));
    r = await postWithSig(rawV, encodeSig(hmacFor("sha512-trunc32", SECRET, rawV), "hex"));
    body = JSON.parse(r.raw);
    assert("sha512-trunc32 hex sig approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 6. HMAC-SHA-384 truncated to 32 bytes, hex.
    rawV = JSON.stringify(preflightEnvelope("gk_test_r3_sha384trunc", r3(0xe6)));
    r = await postWithSig(rawV, encodeSig(hmacFor("sha384-trunc32", SECRET, rawV), "hex"));
    body = JSON.parse(r.raw);
    assert("sha384-trunc32 hex sig approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 7. Key = SHA256(secret + body agent_id).
    let envR3 = preflightEnvelope("gk_test_r3_keyagent", r3(0xe7));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, hmacFor("sha256", crypto.createHash("sha256").update(SECRET + PREFLIGHT_AGENT_ID).digest(), rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("sha256(secret+agentid) key approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 8. Key = HMAC-SHA256(secret, body agent_id).
    envR3 = preflightEnvelope("gk_test_r3_keyhmac", r3(0xe8));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, hmacFor("sha256", crypto.createHmac("sha256", SECRET).update(PREFLIGHT_AGENT_ID).digest(), rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("hmac(secret,agentid) key approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 9. Key = SHA256(secret + "agent-games").
    envR3 = preflightEnvelope("gk_test_r3_keyag", r3(0xe9));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, hmacFor("sha256", crypto.createHash("sha256").update(SECRET + "agent-games").digest(), rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("sha256(secret+agent-games) key approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 10. Payload = the nonce field alone.
    envR3 = preflightEnvelope("gk_test_r3_nonce", r3(0xea));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, hmacFor("sha256", SECRET, envR3.nonce).toString("hex"));
    body = JSON.parse(r.raw);
    assert("nonce-only payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 11. Payload = type + nonce.
    envR3 = preflightEnvelope("gk_test_r3_typenonce", r3(0xeb));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, hmacFor("sha256", SECRET, envR3.type + envR3.nonce).toString("hex"));
    body = JSON.parse(r.raw);
    assert("type+nonce payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 12. Payload = agent_id + nonce.
    envR3 = preflightEnvelope("gk_test_r3_agentnonce", r3(0xec));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, hmacFor("sha256", SECRET, envR3.agent_id + envR3.nonce).toString("hex"));
    body = JSON.parse(r.raw);
    assert("agentid+nonce payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 13. Payload = canonical JSON of the envelope WITHOUT the type field.
    envR3 = preflightEnvelope("gk_test_r3_notype", r3(0xed));
    rawV = JSON.stringify(envR3);
    const { type: _t, ...noType } = envR3;
    r = await postWithSig(rawV, hmacFor("sha256", SECRET, canonicalJson(noType)).toString("hex"));
    body = JSON.parse(r.raw);
    assert("no-type canonical payload approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 14. Signature = hex with a 0x prefix.
    envR3 = preflightEnvelope("gk_test_r3_0x", r3(0xee));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, "0x" + hmacFor("sha256", SECRET, rawV).toString("hex"));
    body = JSON.parse(r.raw);
    assert("0x-prefixed hex sig approves", r.status === 200 && body.decision === "APPROVE", r.raw.slice(0, 200));

    // 15. Negative control: SHA-384 + base64 with a WRONG key.
    envR3 = preflightEnvelope("gk_test_r3_sha384wrong", r3(0xef));
    rawV = JSON.stringify(envR3);
    r = await postWithSig(rawV, encodeSig(hmacFor("sha384", "wrong-secret", rawV), "base64"));
    assert("sha384 + wrong key still 401", r.status === 401, `status=${r.status}`);

    // 16. Negative control: BOTH signature headers wrong.
    envR3 = preflightEnvelope("gk_test_r3_bothwrong", r3(0xf0));
    rawV = JSON.stringify(envR3);
    r = await postRaw(rawV, {
      "x-agent-games-signature": hmacFor("sha256", "wrong-secret", rawV).toString("hex"),
      signature: hmacFor("sha256", "wrong-secret-2", rawV).toString("hex"),
    });
    assert("both signature headers wrong still 401", r.status === 401, `status=${r.status}`);
  } finally {
    server.kill("SIGTERM");
  }

  // Server without a secret must refuse tasks with 503.
  console.log("== no secret configured -> 503 ==");
  const server2 = spawn("node", [path.join(__dirname, "..", "server.js")], {
    env: { ...process.env, PORT: String(PORT + 1) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  try {
    // Give the second server a moment to start, then POST directly.
    await new Promise((r) => setTimeout(r, 2500));
    // Direct POST to the second server (no secret configured).
    const raw = JSON.stringify(envelope("gk_test_nosecret", validInput()));
    const r2 = await new Promise((resolve, reject) => {
      const req = http.request(
        `http://127.0.0.1:${PORT + 1}/task`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-agent-games-signature": crypto
              .createHmac("sha256", SECRET)
              .update(raw)
              .digest("hex"),
            "content-length": Buffer.byteLength(raw),
          },
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode }));
        }
      );
      req.on("error", reject);
      req.end(raw);
    });
    assert("no-secret 503", r2.status === 503, `status=${r2.status}`);
  } finally {
    server2.kill("SIGTERM");
  }

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  console.error("TEST FATAL", e);
  process.exit(1);
});
