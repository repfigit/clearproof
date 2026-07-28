#!/usr/bin/env node
/**
 * check_eip2537.mjs — probe EIP-2537 (BLS12-381) precompile availability
 * across clearproof target chains (ADR 0002, Open Task 2).
 *
 * Method: eth_call to the PAIRING precompile (0x0f) with one byte of invalid
 * input. On chains with EIP-2537 the precompile reverts on bad input; on
 * chains without it, 0x0f is an empty address and the call returns "0x".
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
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 12000);
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_call",
          params: [{ to: "0x000000000000000000000000000000000000000f", data: "0xff" }, "latest"],
        }),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      const j = await res.json();
      let status;
      if (j.error) {
        status = "PRESENT (precompile reverted on bad input)";
      } else if (j.result === "0x") {
        status = "ABSENT (empty return, no precompile)";
        absent += 1;
      } else {
        status = `UNEXPECTED result=${j.result}`;
      }
      console.log(`${name.padEnd(18)} ${status}`);
      reported = true;
      break;
    } catch (e) {
      if (url === urls[urls.length - 1]) {
        console.log(`${name.padEnd(18)} RPC-ERROR ${e.message.slice(0, 60)}`);
      }
    }
  }
  if (!reported) absent += 1;
}

console.log(`\n${absent === 0 ? "All chains have EIP-2537." : `${absent} chain(s) without confirmed EIP-2537.`}`);
process.exit(absent === 0 ? 0 : 1);
