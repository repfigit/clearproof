# Clearproof documentation site

The public site is https://docs.clearproof.world. Its MDX pages describe the
development checkout; published npm package versions are identified separately.
Keep the matching articles in `packages/content/content/topics/` synchronized.

From the repository root:

```bash
npm install
npm run build --workspace @clearproof/content
npm run build --workspace @clearproof/docs
npm run dev --workspace @clearproof/docs
```

Run `npm run test:coverage --workspace @clearproof/docs` after building the
content package. These tests invoke the content API handlers with the real
catalogue and Next.js responses, checking every listed entry and unknown-slug
errors. Layout unit tests check page-map loading, navigation/footer composition,
error propagation and MDX component overrides using controlled Nextra dependencies.
Coverage includes all authored TS/TSX modules and requires 100% of measured
statements, branches, functions and lines. This report does not measure MDX page
rendering, browser interactions or deployment tracing; check those separately.

Use Node.js 24 LTS to match the Vercel project. Run one docs build or development
server at a time because they share `.next` output.

The root npm overrides pin Zod to 4.3.6 for Nextra only. Nextra 4.6.1 removes
`children` before validating its required layout schema, which fails with Zod
4.4.3. See [upstream issue 5036](https://github.com/shuding/nextra/issues/5036).
Remove these overrides after upgrading to a fixed Nextra release and checking
all pages, including the 404 page. Development uses Webpack to avoid the current
Turbopack MDX import-alias failure in this monorepo.

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
