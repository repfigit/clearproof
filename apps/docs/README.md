# Clearproof documentation site

The public site is https://docs.clearproof.world. Its MDX pages describe the
development checkout; published npm package versions are identified separately.
Keep the matching articles in `packages/content/content/topics/` synchronized.

From the repository root:

```bash
npm ci
npm run build --workspace @clearproof/content
npm run build --workspace @clearproof/docs
npm run dev --workspace @clearproof/docs
```

Run `npm run test:coverage --workspace @clearproof/docs` after building the
content package. These tests invoke the content API handlers with the real
catalogue and Next.js responses, checking every listed entry and unknown-slug
errors. Layout unit tests check page-map loading, navigation/footer composition,
error propagation and MDX component overrides using controlled Nextra dependencies.
Coverage includes authored app TS/TSX modules and the MDX registry and requires 100% of measured
statements, branches, functions and lines. This report does not measure MDX page
rendering, browser interactions or deployment tracing.

Run the production browser/server acceptance suite separately:

```bash
npm exec --workspace @clearproof/docs -- playwright install --with-deps chromium firefox webkit
npm run build --workspace @clearproof/content
npm run build --workspace @clearproof/docs
npm run test:e2e --workspace @clearproof/docs
```

For a prebuilt production deployment, regenerate the build output at the commit
being deployed before deploying it. The `.vercel/output` directory is not rebuilt
by `vercel deploy --prebuilt`; deploying with a stale output directory republishes
the old site regardless of the current source. From `apps/docs`, run
`vercel build --prod` after building both workspaces, then copy
`.vercel/project.json` and `.vercel/output` to the repository root `.vercel` and
run `vercel deploy --prebuilt --prod` from the root as described below.

Playwright discovers every MDX page and checks desktop/mobile Chromium, Firefox
and WebKit rendering, canonical metadata, browser errors, the Mermaid SVG,
client navigation/back, the 404 page and the built content API. It also checks
that the shared project catalogue matches status text and that promoted articles
resolve. It owns a production server on 127.0.0.1:43135 and refuses to reuse
another process. These checks exercise the local production build; hosted
deployment tracing requires separate verification.

`packages/content/src/project.ts` owns the verified release, proof profile,
assurance and capacity statements consumed by docs and the separate homepage.
`/api/content/project` combines these with the request-time approved explainer
catalogue, applying publication dates and the pause switch. Deploy this endpoint
before a homepage change that consumes it. Technical pages declare static
metadata because Nextra's metadata-only compiler removes imports. The unit
inventory check prevents those declarations from drifting from the sitemap.

Use Node.js 24 LTS to match the Vercel project. Run one docs build or development
server at a time because they share `.next` output.

The root npm overrides pin Zod to 4.3.6 for Nextra only. Nextra 4.6.1 removes
`children` before validating its required layout schema, which fails with Zod
4.4.3. See [upstream issue 5036](https://github.com/shuding/nextra/issues/5036).
Remove these overrides after upgrading to a fixed Nextra release and checking
all pages, including the 404 page. Development uses Webpack to avoid the current
Turbopack MDX import-alias failure in this monorepo.

The root PostCSS override selects 8.5.29 to replace Next 15's older transitive
pin. It addresses the upstream source-map disclosure fixes, including
[GHSA-fxqj-rqcc-2cmp](https://github.com/postcss/postcss/security/advisories/GHSA-fxqj-rqcc-2cmp).
Production audit findings in Nextra's braces/fast-glob build chain and the
circomlibjs/ethers 5 comparison tooling still need upstream disposition; do not
force major framework downgrades merely to reduce the audit count. No public
route accepts visitor-supplied glob patterns or CSS for compilation. The native
Python Poseidon path does not use circomlibjs's wallet/signature implementation.

The content API keeps `@clearproof/content` external to the server bundle so its
Markdown/YAML paths remain relative to the package. The explicit Webpack external
also covers npm workspace symlinks, which Next 15's package matcher misses.
Check `/api/content/manifest` and `/api/content/topics/quickstart` after building
and after deployment; successful page generation alone does not exercise them.

For a local prebuilt Vercel deployment, build from `apps/docs` with the `docs`
project linked. Copy its `.vercel/project.json` and `.vercel/output` into a real
`.vercel` directory at the repository root, preserving internal output symlinks.
Run `vercel deploy --prebuilt --prod` from that root so traced workspace paths
resolve correctly. Do not make the root `.vercel` directory itself a symlink.
Verify the public domain and content API after the deployment becomes ready.

Before updating public claims, check authenticated repository visibility,
unauthenticated npm access and clean installation, the deployment manifest and
actual testnet bytecode. Source features, published packages, deployed contracts
and planned work are separate states. Audit, performance, interoperability and
regulatory claims require their own evidence.
