/**
 * malljb234-gatekeeper — Proof Gatekeeper agent for zkVerify Agent Games S01.
 *
 * Plain Node.js HTTP server (no framework). All decision/proof logic lives
 * in lib/gatekeeper.js, shared with the Vercel serverless handler
 * (api/index.js) so both runtimes behave identically.
 *
 *   npm install
 *   AGENT_GAMES_HMAC_SECRET=<secret from the Agent Games dashboard> node server.js
 *
 *   GET  /health   -> { status: "ok", ... } (works without a secret)
 *   POST / | /task -> signed task envelope, answered with decision + proof
 *
 * Environment: PORT (default 3000), AGENT_GAMES_HMAC_SECRET (required for
 * tasks), REGISTERED_VK_HASH (default = official gatekeeper vkHash),
 * STATE_PATH (default <repo-root>/state.json).
 */
"use strict";

const http = require("http");
const gatekeeper = require("./lib/gatekeeper");

const PORT = parseInt(process.env.PORT || "3000", 10);

const server = http.createServer((req, res) => {
  // Read the raw body first — HMAC is verified on the raw bytes.
  const chunks = [];
  req.on("data", (c) => {
    chunks.push(c);
    if (Buffer.concat(chunks).length > 1_000_000) req.destroy();
  });
  req.on("end", async () => {
    try {
      const result = await gatekeeper.handleRequest({
        method: req.method,
        url: req.url,
        headers: req.headers,
        rawBody: Buffer.concat(chunks),
      });
      res.writeHead(result.status, result.headers);
      res.end(result.body);
    } catch (e) {
      console.error("request handler error:", e);
      // Fail closed: any unhandled error -> REJECT without proof.
      const body = JSON.stringify({
        decision: "REJECT",
        reason_code: "INVALID_TASK",
        proof_tx: "",
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    }
  });
});

server.listen(PORT, () => {
  console.log(
    `malljb234-gatekeeper listening on :${PORT} (hmac ${
      process.env.AGENT_GAMES_HMAC_SECRET ? "configured" : "NOT CONFIGURED"
    })`
  );
});
