// Build the package's circuit sources from the repository's canonical circuits/ directory.
// Relative includes of the repo-root circomlib ("../node_modules/circomlib/...") are rewritten to
// "circomlib/...", so consumers compile with `-l node_modules`. Nothing else is changed.
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = join(here, '..');
const source = join(pkg, '..', '..', 'circuits');
const out = join(pkg, 'circuits');
const sha256 = (data) => createHash('sha256').update(data).digest('hex');

export function rewriteIncludes(text) {
  return text.replace(/include "(?:\.\.\/)+node_modules\/circomlib\//g, 'include "circomlib/');
}

function circomFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === 'lib' ? circomFiles(path) : [];
    return entry.name.endsWith('.circom') ? [path] : [];
  });
}

export function sync() {
  rmSync(out, { recursive: true, force: true });
  const files = circomFiles(source).sort();
  if (files.length === 0) throw new Error(`No circuits found in ${source}`);
  const manifest = {};
  for (const file of files) {
    const rel = relative(source, file);
    const original = readFileSync(file, 'utf8');
    const rewritten = rewriteIncludes(original);
    if (/include "(?:\.\.\/)+node_modules\//.test(rewritten)) throw new Error(`Unrewritten include in ${rel}`);
    mkdirSync(dirname(join(out, rel)), { recursive: true });
    writeFileSync(join(out, rel), rewritten);
    manifest[rel] = { repository_sha256: sha256(original), package_sha256: sha256(rewritten) };
  }
  writeFileSync(join(out, 'MANIFEST.json'), JSON.stringify({ source: 'circuits/', files: manifest }, null, 2) + '\n');
  return Object.keys(manifest);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const written = sync();
  console.log(`Synced ${written.length} circuit files into packages/circuits/circuits/`);
}
