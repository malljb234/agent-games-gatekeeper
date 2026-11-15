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
