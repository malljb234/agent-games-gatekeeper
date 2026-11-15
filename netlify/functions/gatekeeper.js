/**
 * Netlify serverless handler for malljb234-gatekeeper (Free plan).
 *
 * netlify/functions/gatekeeper.js maps to
 *   https://<site>.netlify.app/.netlify/functions/gatekeeper
 * — register THAT URL as the Agent Endpoint on the Agent Games dashboard.
 * (netlify.toml also rewrites /, /health, /task and /api to this function,
 * so the site root answers health the same way.)
 *
 * Behaviour is identical to server.js and api/index.js: the same
 * lib/gatekeeper.js core handles every request. Netlify-specific notes:
 *   - Event shape: event.httpMethod, event.headers (lowercase keys),
 *     event.body (string; base64 when event.isBase64Encoded), event.path.
 *     The HMAC must be verified over the exact raw bytes, so the body is
 *     decoded to a Buffer exactly as received (no JSON re-serialising).
 *   - The filesystem is read-only except /tmp, so persistent state goes
 *     to /tmp/gatekeeper-state.json (best-effort) and in-memory state
 *     survives only while the instance is warm. A cold start may
 *     therefore forget a seen proof_tx / cached task — the fail-closed
 *     checklist still decides correctly; only the PROOF_REUSED trap and
 *     byte-identical replay depend on remembered state.
 *   - Circuit files (circuits/gatekeeper.wasm + gatekeeper_final.zkey)
 *     are bundled via `included_files` in netlify.toml and resolved by
 *     lib/gatekeeper.js, which tries several candidate paths (local,
 *     cwd-relative, and Netlify-bundled layouts).
 *   - Free-plan synchronous functions have a 10s execution limit. The
 *     proof itself takes ~0.9-1.6s and a cold start a few seconds, so
 *     there is comfortable headroom inside the platform's 60s window.
 *   - The handler answers GET with the health JSON on ANY path and treats
 *     ANY POST as a task POST.
 */
"use strict";

// State file must live in /tmp on Netlify (only writable dir). Set BEFORE
// requiring the core module, which reads STATE_PATH at load time.
process.env.STATE_PATH = process.env.STATE_PATH || "/tmp/gatekeeper-state.json";

const gatekeeper = require("../../lib/gatekeeper");

exports.handler = async (event, context) => {
  const method = (event.httpMethod || "GET").toUpperCase();

  let rawBody = Buffer.alloc(0);
  if (event.body) {
    rawBody = event.isBase64Encoded
      ? Buffer.from(event.body, "base64")
      : Buffer.from(event.body, "utf8");
  }
  if (rawBody.length > 1_000_000) {
    return {
      statusCode: 413,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "payload_too_large" }),
    };
  }

  // Any GET is a health check; any POST is a task.
  const url = method === "GET" ? "/health" : "/task";
  const headers = {};
  for (const [k, v] of Object.entries(event.headers || {})) {
    headers[String(k).toLowerCase()] = v;
  }

  try {
    const result = await gatekeeper.handleRequest({
      method,
      url,
      headers,
      rawBody,
    });
    return {
      statusCode: result.status,
      headers: result.headers,
      body: result.body,
    };
  } catch (e) {
    console.error("request handler error:", e);
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        decision: "REJECT",
        reason_code: "INVALID_TASK",
        proof_tx: "",
      }),
    };
  }
};
