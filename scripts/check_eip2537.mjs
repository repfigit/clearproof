#!/usr/bin/env node
/**
 * check_eip2537.mjs — probe EIP-2537 (BLS12-381) precompile availability
 * across clearproof target chains (ADR 0002, Open Task 2).
 *
 * Method: eth_call to PAIRING (0x0f) with one valid pair of infinity points.
 * EIP-2537 encodes this pair as 384 zero bytes and returns a 32-byte true value.
 * Empty returns, RPC errors and unexpected results do not confirm support.
 * Reference: https://eips.ethereum.org/EIPS/eip-2537#abi-for-pairing
 *
 * Usage: node scripts/check_eip2537.mjs
 */
const nets = [
  ["sepolia", ["https://ethereum-sepolia-rpc.publicnode.com", "https://sepolia.drpc.org"]],
  ["ethereum", ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"]],
  ["base-sepolia", ["https://sepolia.base.org"]],
  ["base", ["https://mainnet.base.org"]],
  ["arbitrum-sepolia", ["https://sepolia-rollup.arbitrum.io/rpc"]],
  ["arbitrum", ["https://arb1.arbitrum.io/rpc"]],
  ["optimism-sepolia", ["https://sepolia.optimism.io"]],
  ["optimism", ["https://mainnet.optimism.io"]],
  ["polygon-amoy", ["https://polygon-amoy-bor-rpc.publicnode.com", "https://rpc.ankr.com/polygon_amoy"]],
  ["polygon", ["https://polygon-rpc.com"]],
];

let absent = 0;
for (const [name, urls] of nets) {
  let reported = false;
  for (const url of urls) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_call",
          params: [{ to: "0x000000000000000000000000000000000000000f", data: "0x" + "00".repeat(384) }, "latest"],
        }),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const j = await res.json();
      if (j.error) throw new Error(`JSON-RPC error: ${j.error.message}`);
      let status;
      if (j.result === "0x" + "00".repeat(31) + "01") {
        status = "PRESENT (pairing check returned true)";
      } else if (j.result === "0x") {
        status = "ABSENT (empty return, no precompile)";
        absent += 1;
      } else {
        status = `UNEXPECTED result=${j.result}`;
        absent += 1;
      }
      console.log(`${name.padEnd(18)} ${status}`);
      reported = true;
      break;
    } catch (e) {
      if (url === urls[urls.length - 1]) {
        console.log(`${name.padEnd(18)} RPC-ERROR ${e.message.slice(0, 60)}`);
      }
    } finally {
      clearTimeout(timer);
    }
  }
  if (!reported) absent += 1;
}

console.log(`\n${absent === 0 ? "All chains have EIP-2537." : `${absent} chain(s) without confirmed EIP-2537.`}`);
process.exit(absent === 0 ? 0 : 1);
