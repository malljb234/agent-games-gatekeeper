// Probe the official gatekeeper circuit: confirm the 13 input signal names
// reported by independent builders, by running fullProve + verify.
// Logs unbuffered to stdout AND probe-results.txt (no pipe buffering).
const fs = require("fs");
const snarkjs = require("snarkjs");
const path = require("path");

const OUT = path.join(__dirname, "probe-results.txt");
fs.writeFileSync(OUT, "");
function log(m) {
  fs.writeSync(1, m + "\n");
  fs.appendFileSync(OUT, m + "\n");
}

const WASM = path.join(__dirname, "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "circuits", "gatekeeper_final.zkey");
const VK = path.join(__dirname, "circuits", "verification_key.json");

const VK_HASH_HEX = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK_HASH_DEC = BigInt(VK_HASH_HEX).toString(10);
const FR_MOD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
log("vkHash decimal: " + VK_HASH_DEC);
log("vkHash < Fr modulus? " + (BigInt(VK_HASH_HEX) < FR_MOD));
log("vkHash mod Fr: " + (BigInt(VK_HASH_HEX) % FR_MOD).toString(10));

const ADDR = "0xDe42000000000000000000000000000000009f01";

function baseInput(overrides = {}) {
  return {
    registeredVkHash: VK_HASH_DEC,
    proofVkHash: VK_HASH_DEC,
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "8430000",
    currentBlock: "8420000",
    recipient: BigInt(ADDR).toString(10),
    conditionRecipient: BigInt(ADDR).toString(10),
    amount: "500",
    maxTransfer: "1000",
    decision: "1",
    taskId: "24",
    salt: "12345",
    ...overrides,
  };
}

async function tryProve(label, input) {
  try {
    const t0 = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      WASM,
      ZKEY
    );
    const ms = Date.now() - t0;
    const vkey = require(VK);
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    log(
      `[${label}] fullProve OK in ${ms}ms, verify=${ok}, publicSignals(${publicSignals.length})=${JSON.stringify(
        publicSignals
      )}`
    );
    return { proof, publicSignals, ok };
  } catch (e) {
    log(`[${label}] FAILED: ${String(e && e.message ? e.message : e).slice(0, 300)}`);
    return null;
  }
}

(async () => {
  log("== valid approve ==");
  await tryProve("valid-approve", baseInput());
  log("== trap: recipient mismatch, decision=approve (must FAIL) ==");
  await tryProve(
    "trap-recipient-approve",
    baseInput({
      conditionRecipient: BigInt("0x1111111111111111111111111111111111111111").toString(10),
      decision: "1",
    })
  );
  log("== trap: recipient mismatch, decision=reject (must SUCCEED) ==");
  await tryProve(
    "trap-recipient-reject",
    baseInput({
      conditionRecipient: BigInt("0x1111111111111111111111111111111111111111").toString(10),
      decision: "0",
    })
  );
  log("== trap: valid inputs, decision=reject (must FAIL) ==");
  await tryProve("valid-reject", baseInput({ decision: "0" }));
  log("== trap: vk mismatch, decision=approve (must FAIL) ==");
  await tryProve("trap-vk-approve", baseInput({ proofVkHash: "12345", decision: "1" }));
  log("== trap: balance below minimum, decision=approve (must FAIL) ==");
  await tryProve("trap-threshold-approve", baseInput({ publicBalance: "999", decision: "1" }));
  log("== trap: expired, decision=approve (must FAIL) ==");
  await tryProve("trap-expired-approve", baseInput({ expiryBlock: "8419999", decision: "1" }));
  log("== trap: amount over cap, decision=approve (must FAIL) ==");
  await tryProve("trap-amount-approve", baseInput({ amount: "1001", decision: "1" }));
  log("DONE");
  process.exit(0);
})().catch((e) => {
  log("FATAL " + (e && e.stack ? e.stack : e));
  process.exit(1);
});
