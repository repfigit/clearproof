#!/usr/bin/env node
/**
 * Poseidon hash helper — reads JSON array of bigint inputs from stdin,
 * outputs the Poseidon hash as a decimal string to stdout.
 *
 * Usage:
 *   echo '[1, 2, 3]' | node scripts/poseidon_hash.js
 *   echo '{"inputs": [1, 2, 3]}' | node scripts/poseidon_hash.js
 *
 * Requires: npm install circomlibjs
 */
const { buildPoseidon } = require("circomlibjs");

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf-8").trim();
  let inputs;
  try {
    const parsed = JSON.parse(raw);
    inputs = Array.isArray(parsed) ? parsed : parsed.inputs;
    if (!Array.isArray(inputs)) {
      throw new Error("Expected a JSON array or {inputs: [...]}");
    }
  } catch (err) {
    process.stderr.write(`Invalid input JSON: ${err.message}\n`);
    process.exit(1);
  }

  const poseidon = await buildPoseidon();
  const hash = poseidon(inputs.map(BigInt));
  // poseidon returns a Uint8Array (F element); convert to decimal string
  const result = poseidon.F.toString(hash, 10);
  process.stdout.write(result + "\n");
}

main().catch((err) => {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
});
