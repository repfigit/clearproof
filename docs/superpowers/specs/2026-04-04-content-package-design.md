# Content Package & CLI Documentation System

**Date:** 2026-04-04
**Status:** Draft
**Author:** Keith + Claude

## Problem

Documentation lives in multiple places (README, docs site MDX, code comments, CLI help stubs) with no shared source. Content drifts between the monorepo and clearproof-web. Developers context-switch between browser and terminal. Recipes in docs are not tested and go stale.

## Solution

A `@clearproof/content` workspace package that serves as the single source of truth for all developer-facing content. Three consumers read from it:

1. **CLI** — `clearproof help`, `clearproof recipes`, `clearproof explain` (workspace dep, bundled at build time)
2. **Docs site** — Nextra pages render content from the package (workspace dep)
3. **clearproof-web** — Fetches content from docs site API routes at build time (cross-repo, no npm publish needed)

## Architecture

```
packages/content/           <- new package, single source of truth
  content/
    topics/*.md             <- help topics (quickstart, circuits, api, etc.)
    recipes/*.md            <- runnable recipes with bash:run blocks
    signals.yaml            <- 16 public signal definitions
  src/
    index.ts                <- public API exports
    topics.ts               <- getTopic(), listTopics()
    recipes.ts              <- getRecipe(), listRecipes(), getRecipeSteps()
    signals.ts              <- getSignal(), listSignals()
    parser.ts               <- frontmatter + markdown parsing
  package.json
  tsconfig.json

packages/cli/               <- existing, adds help/recipes/explain commands
  src/
    commands/help.ts        <- clearproof help [topic]
    commands/recipes.ts     <- clearproof recipes [name] [--run]
    commands/explain.ts     <- clearproof explain <signal>
    render.ts               <- markdown-to-terminal renderer

apps/docs/                  <- existing Nextra site
  app/api/content/          <- new API routes for clearproof-web
    topics/[slug]/route.ts
    recipes/[slug]/route.ts
    signals/[slug]/route.ts
    manifest/route.ts
```

## Content Package API

### Types

```typescript
interface TopicMeta {
  slug: string
  title: string
  category: string
  order: number
}

interface Topic extends TopicMeta {
  body: string            // raw markdown body (no frontmatter)
}

interface RecipeMeta {
  slug: string
  title: string
  prereqs: string[]
  estimatedTime: string
}

interface Recipe extends RecipeMeta {
  body: string
  steps: RecipeStep[]
}

interface RecipeStep {
  description: string
  command: string         // the bash command to run
  expected: string        // what success looks like
}

interface Signal {
  index: number
  name: string
  type: string            // "field" | "uint64" | "uint16" | "bit"
  description: string
  source: string          // source circom file
  onChainUsage: string    // how ComplianceRegistry uses it
  isOutput: boolean
}
```

### Functions

```typescript
// Topics
listTopics(): TopicMeta[]
getTopic(slug: string): Topic | null

// Recipes
listRecipes(): RecipeMeta[]
getRecipe(slug: string): Recipe | null
getRecipeSteps(slug: string): RecipeStep[]

// Signals
listSignals(): Signal[]
getSignal(name: string): Signal | null
```

### Content reads at build time

The parser reads `.md` files and `signals.yaml` from disk using `fs.readFileSync`. Content files are included in the package's `files` field in `package.json` so they ship with the package. At runtime:

- CLI resolves content relative to `__dirname` (the compiled JS location in `node_modules/@clearproof/content/`)
- Docs site reads at Next.js build/SSR time via the workspace dependency
- Content is read from disk, not bundled into JS — keeps the package small and files inspectable

## Content Format

### Topic files (`content/topics/*.md`)

```markdown
---
title: Quick Start
category: getting-started
order: 1
cli-topic: quickstart
---

## Prerequisites

- Python 3.11+ with [uv](https://docs.astral.sh/uv/)
- Node.js 20+
- circom 2.2.2+

## Install

```bash
git clone https://github.com/repfigit/clearproof.git
cd clearproof
npm install && uv sync --all-extras
```
...
```

### Recipe files (`content/recipes/*.md`)

````markdown
---
title: Generate a Compliance Proof
prereqs:
  - api-running
  - circuits-compiled
estimated-time: 2 min
---

# Generate a Compliance Proof

## 1. Issue a credential

```bash:run
curl -s -X POST http://localhost:8000/credential/issue \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"issuer_did":"did:web:vasp.example.com","subject_wallet":"0x1234abcd","jurisdiction":"US","kyc_tier":"retail"}'
```

Expected: 200 with `credential_id` and `commitment`

## 2. Generate proof

```bash:run
curl -s -X POST http://localhost:8000/proof/generate \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"credential_id":"$CRED_ID","wallet_address":"0x1234abcd","amount_usd":500,"asset":"USDC","destination_wallet":"0xabcd1234","jurisdiction":"US","idempotency_key":"recipe-test-001"}'
```

Expected: 200 with `compliance_proof` and `encrypted_pii`
````

### Signals file (`content/signals.yaml`)

```yaml
signals:
  - index: 0
    name: is_compliant
    type: bit
    description: 1 if all compliance checks pass
    source: circuits/compliance.circom
    onChainUsage: Must equal 1 for proof acceptance
    isOutput: true

  - index: 1
    name: sar_review_flag
    type: bit
    description: 1 if amount_tier >= 3 (triggers human review)
    source: circuits/amount_tier.circom
    onChainUsage: Stored in userSARFlags mapping
    isOutput: true

  - index: 2
    name: sanctions_tree_root
    type: field
    description: Merkle root of sorted OFAC/UN/EU sanctions tree
    source: circuits/compliance.circom
    onChainUsage: Checked against SanctionsOracle.root()
    isOutput: false
  # ... all 16 signals
```

## CLI Commands

### `clearproof help [topic]`

```
$ clearproof help

  Available topics:

    quickstart       Getting started in 5 minutes
    architecture     System overview and data flow
    circuits         Circuit signals and constraints
    contracts        On-chain contracts and addresses
    api              API endpoints, auth, rate limits
    sdk              TypeScript SDK usage
    security         Security properties and threat model
    troubleshooting  Common issues and fixes

  Usage: clearproof help <topic>

$ clearproof help circuits

  # Circuit Signals Reference

  The compliance circuit has 16 public signals (2 outputs + 14 inputs)...
```

### `clearproof recipes [name] [--run]`

```
$ clearproof recipes

  Available recipes:

    generate-proof     Issue credential + generate ZK proof (2 min)
    verify-proof       Verify a proof off-chain (1 min)
    verify-onchain     Submit proof to ComplianceRegistry (3 min)
    deploy-contracts   Deploy to Sepolia testnet (5 min)
    update-sanctions   Rebuild sanctions tree + relay (2 min)
    full-walkthrough   End-to-end compliance flow (10 min)

  Usage: clearproof recipes <name>
         clearproof recipes <name> --run   (execute interactively)

$ clearproof recipes generate-proof --run

  # Generate a Compliance Proof

  Prereqs: api-running, circuits-compiled

  ## Step 1: Issue a credential

  > curl -s -X POST http://localhost:8000/credential/issue ...

  Run this step? [Y/n] _
```

### `clearproof explain <signal>`

```
$ clearproof explain credential_nullifier

  credential_nullifier (public signal #14)

  Poseidon(credential_commitment, transfer_id_hash)

  One-time-use value stored on-chain. Prevents the same credential
  from being used to generate multiple proofs for the same transfer.
  The contract reverts if this nullifier has been seen before.

  Type:     BN128 field element
  Index:    14
  Output:   no (public input)
  Source:   circuits/credential_validity.circom
  On-chain: Stored in usedNullifiers mapping, checked for uniqueness
```

## Docs Site API Routes

Thin JSON wrappers over the content package, consumed by clearproof-web at build time.

### `GET /api/content/topics/[slug]`

Returns `Topic` as JSON. 404 if not found.

### `GET /api/content/recipes/[slug]`

Returns `Recipe` as JSON. 404 if not found.

### `GET /api/content/signals/[slug]`

Returns `Signal` as JSON. 404 if not found.

### `GET /api/content/manifest`

Returns:
```json
{
  "topics": [{ "slug": "quickstart", "title": "Quick Start", "category": "getting-started" }],
  "recipes": [{ "slug": "generate-proof", "title": "Generate a Compliance Proof" }],
  "signals": [{ "index": 0, "name": "is_compliant" }]
}
```

clearproof-web fetches the manifest at build time (ISR or SSG) and renders feature lists, contract addresses, and signal summaries from the canonical source.

## Terminal Rendering

The CLI needs a basic markdown-to-terminal renderer (`packages/cli/src/render.ts`):

- `#` headers -> bold + color
- `` ```bash `` code blocks -> indented + dim background (if terminal supports)
- `**bold**` -> ANSI bold
- `[links](url)` -> `text (url)` in dim
- Tables -> aligned columns
- Strip HTML tags

No external dependency needed. Chalk (common in CLI projects) plus ~100 lines of regex-based rendering. Not a full terminal Markdown engine, just good enough for help text.

## Docs Site Migration

Existing MDX pages in `apps/docs/app/docs/` are replaced by thin wrappers that import from `@clearproof/content`. Migration path:

1. Create `packages/content/` with initial content extracted from current MDX files
2. Update `apps/docs/` pages to import from `@clearproof/content`
3. Remove duplicated content from MDX files
4. Add API routes under `apps/docs/app/api/content/`

Existing Nextra theme, layout, navigation, and Vercel deployment are unchanged.

## Recipe Testing

`make test-recipes` runs recipe steps against a local API:

1. Starts the API server (`make dev` in background)
2. Imports `getRecipeSteps()` for each recipe
3. Executes each `bash:run` command via `execFile` (not `exec`, to prevent shell injection)
4. Asserts non-empty output and expected status codes
5. Kills the API server

This runs in CI as a separate job, gated on `python-tests` and `hardhat-tests` passing first. Recipes that reference on-chain operations (`verify-onchain`, `deploy-contracts`) are skipped in CI unless `SEPOLIA_RPC_URL` is set.

## What This Does NOT Cover

- **npm publishing of `@clearproof/content`** — stays as workspace-only package. clearproof-web uses the API routes instead.
- **Man pages** — unnecessary given the CLI help system.
- **OpenAPI auto-import** — the API docs page is hand-written for clarity. FastAPI's Swagger UI at `/docs` serves as the interactive reference.
- **i18n** — English only for now.
- **Search** — not in scope. Nextra has built-in search for the docs site; the CLI uses exact topic/signal matching.

## File Count Estimate

| Component | New files | Modified files |
|-----------|-----------|----------------|
| `packages/content/` | ~20 (8 topics + 6 recipes + signals.yaml + 5 src files) | 0 |
| `packages/cli/` | 4 (help.ts, recipes.ts, explain.ts, render.ts) | 1 (index.ts) |
| `apps/docs/` | 5 (API routes) | ~13 (migrate MDX to content imports) |
| Root | 0 | 1 (turbo.json) |

Total: ~30 new files, ~15 modified files.
