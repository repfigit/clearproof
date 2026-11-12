import fs from 'fs';
import path from 'path';
import { describe, expect, it } from 'vitest';

import { getRecipe, listRecipes } from '../src/recipes.js';

const contentRoot = path.resolve(__dirname, '../content');
const repoRoot = path.resolve(__dirname, '../../..');
const contractsRoot = path.join(repoRoot, 'packages/contracts');

function markdownFiles(section: string): string[] {
  return fs.readdirSync(path.join(contentRoot, section)).filter(name => name.endsWith('.md')).sort()
    .map(name => path.join(section, name));
}

/**
 * Repository paths named in a document: tokens that start at a top-level source
 * directory and end in a file extension or a trailing slash, plus the path part
 * of github.com/repfigit/clearproof blob/tree links. Build outputs, wildcards and
 * placeholders are not checked.
 */
function repoPathReferences(markdown: string): string[] {
  const found = new Set<string>();
  for (const match of markdown.matchAll(/github\.com\/repfigit\/clearproof\/(?:blob|tree)\/main\/([A-Za-z0-9_.\/-]+)/g)) {
    found.add(match[1].replace(/[.,]+$/, ''));
  }
  const local = /(?<![A-Za-z0-9_.\/$}-])(?:scripts|packages|docs|specs|circuits|src|tests|config|deployments|apps|protos)\/[A-Za-z0-9_.\/-]*(?:\.(?:md|ts|py|sh|mjs|js|json|circom|sol|yml)\b|\/(?![A-Za-z0-9_.*<-]))/g;
  for (const match of markdown.matchAll(local)) {
    if (!/(?:^|\/)(?:dist|node_modules|artifacts)\//.test(match[0])) found.add(match[0]);
  }
  return [...found].sort();
}

/** Paths that exist only inside a packed npm tarball, written by that package's prepack script. */
const packedOnly = new Set(['circuits/MANIFEST.json']);

const existsInRepo = (reference: string) => packedOnly.has(reference) ||
  [repoRoot, contractsRoot].some(root => fs.existsSync(path.join(root, reference)));

function readRecipe(name: string): string {
  return fs.readFileSync(path.join(contentRoot, 'recipes', `${name}.md`), 'utf-8');
}

describe('developer recipes', () => {
  it('include API-key auth on protected API calls', () => {
    for (const recipe of ['generate-proof', 'full-walkthrough', 'verify-proof']) {
      const markdown = readRecipe(recipe);
      const protectedCalls = markdown.match(/curl -s -X POST http:\/\/localhost:8000\/(?:credential|proof)\/[^\s]+/g) ?? [];

      expect(protectedCalls.length, `${recipe} should exercise protected endpoints`).toBeGreaterThan(0);
      expect(markdown, `${recipe} should define CLEARPROOF_API_KEY`).toContain('CLEARPROOF_API_KEY');
      expect(markdown, `${recipe} should send X-API-Key`).toContain('-H "X-API-Key: $CLEARPROOF_API_KEY"');
    }
  });

  it('documents environment required by on-chain scripts', () => {
    const markdown = readRecipe('verify-onchain');

    expect(markdown).toContain('DEPLOYER_PRIVATE_KEY');
    expect(markdown).toContain('PROOF_PATH');
    expect(markdown).toContain('TRANSFER_ID');
    expect(markdown).toContain('VASP_DID');
    expect(markdown).toContain('scripts/verify-onchain.ts');
    expect(markdown).toContain('scripts/check-transfer.ts');
  });

  it('finds path references and ignores site routes, build outputs and placeholders', () => {
    expect(repoPathReferences([
      'Run `scripts/deploy.ts`, then (cd packages/contracts && npx hardhat run scripts/missing-script.ts).',
      'Records go to `deployments/sepolia/` and `packages/contracts/deployments/sepolia.json`.',
      'See [guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/onboarding.md).',
      'Not checked: /docs/status, https://docs.clearproof.world/docs/quickstart, packages/*/dist,',
      'node packages/cli/dist/index.js, $PWD/artifacts/latest_proof.json, $DIR/scripts/other.ts, packages/contracts.',
    ].join('\n'))).toEqual([
      'deployments/sepolia/',
      'docs/operations/onboarding.md',
      'packages/contracts/deployments/sepolia.json',
      'scripts/deploy.ts',
      'scripts/missing-script.ts',
    ]);
    expect(existsInRepo('scripts/deploy.ts')).toBe(true);
    expect(existsInRepo('scripts/missing-script.ts')).toBe(false);
    expect(existsInRepo('deployments/sepolia/')).toBe(false);
  });

  it('reference only repository paths that exist', () => {
    const files = [...markdownFiles('recipes'), ...markdownFiles('topics')];
    expect(files.length).toBeGreaterThan(10);
    const missing = files.flatMap(file =>
      repoPathReferences(fs.readFileSync(path.join(contentRoot, file), 'utf-8'))
        .filter(reference => !existsInRepo(reference))
        .map(reference => `${file}: ${reference}`));
    expect(missing).toEqual([]);
  });

  it('name the signer variable that Hardhat reads', () => {
    const config = fs.readFileSync(path.join(contractsRoot, 'hardhat.config.ts'), 'utf-8');
    expect(config).toContain('process.env.DEPLOYER_PRIVATE_KEY');
    for (const file of [...markdownFiles('recipes'), ...markdownFiles('topics')]) {
      const markdown = fs.readFileSync(path.join(contentRoot, file), 'utf-8');
      expect(markdown, `${file} should use DEPLOYER_PRIVATE_KEY`).not.toMatch(/(?<![A-Z_])PRIVATE_KEY\b/);
    }
  });

  it('keep every runnable step valid from the starting directory of one shell session', () => {
    // `clearproof recipes --run` runs all steps in one shell, so a bare `cd` in one step
    // would break the relative paths of the next. Directory changes belong in a subshell.
    const recipes = listRecipes();
    expect(recipes.length).toBeGreaterThan(0);
    for (const { slug } of recipes) {
      for (const step of getRecipe(slug)!.steps) {
        expect(step.command, `${slug}: empty runnable step`).not.toBe('');
        const outsideSubshells = step.command.replace(/\([^()]*\)/g, '');
        expect(outsideSubshells, `${slug}: "${step.description}" changes directory for later steps`)
          .not.toMatch(/(?:^|&&|;|\|\|)\s*cd\s/m);
      }
    }
  });
});
