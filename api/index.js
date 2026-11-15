/**
 * Vercel serverless handler for malljb234-gatekeeper (Hobby plan).
 *
 * api/index.js maps to https://<project>.vercel.app/api — register THAT URL
 * as the Agent Endpoint on the Agent Games dashboard.
 *
 * Behaviour is identical to server.js: the same lib/gatekeeper.js core
 * handles every request. Two Vercel-specific notes:
 *   - The filesystem is read-only except /tmp, so persistent state goes to
 *     /tmp/gatekeeper-state.json (best-effort) and in-memory state survives
 *     only while the instance is warm. A cold start may therefore forget a
 *     seen proof_tx / cached task — the fail-closed checklist still decides
 *     correctly; only the PROOF_REUSED trap and byte-identical replay depend
 *     on remembered state.
 *   - The handler answers GET with the health JSON on ANY path and treats
 *     ANY POST as a task POST, so the platform's health check works whether
 *     it calls the endpoint URL itself or /health.
 *   - Raw body is read from the request stream (no body parser) because
 *     the HMAC must be verified over the exact raw bytes.
 *   - maxDuration is set to 60s in vercel.json (Fluid Compute default on
 *     Hobby is 300s; the proof itself takes ~2s, cold start a few more).
 */
"use strict";

// State file must live in /tmp on Vercel (only writable dir). Set BEFORE
// requiring the core module, which reads STATE_PATH at load time.
process.env.STATE_PATH = process.env.STATE_PATH || "/tmp/gatekeeper-state.json";

const gatekeeper = require("../lib/gatekeeper");

module.exports = async (req, res) => {
  const chunks = [];
  try {
    for await (const chunk of req) {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > 1_000_000) {
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "payload_too_large" }));
        return;
      }
    }
  } catch (e) {
    console.error("body read error:", e);
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "bad_request" }));
    return;
  }

  // Normalise the path: on Vercel this handler serves /api (and /api/index).
  // Any GET is a health check; any POST is a task.
  const method = (req.method || "GET").toUpperCase();
  const url = method === "GET" ? "/health" : "/task";

  try {
    const result = await gatekeeper.handleRequest({
      method,
      url,
      headers: req.headers || {},
      rawBody: Buffer.concat(chunks),
    });
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (e) {
    console.error("request handler error:", e);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        decision: "REJECT",
        reason_code: "INVALID_TASK",
        proof_tx: "",
      })
    );
  }
};
