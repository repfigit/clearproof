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

Use Node.js 24 LTS to match the Vercel project. Run one docs build or development
server at a time because they share `.next` output.

The root npm overrides pin Zod to 4.3.6 for Nextra only. Nextra 4.6.1 removes
`children` before validating its required layout schema, which fails with Zod
4.4.3. See [upstream issue 5036](https://github.com/shuding/nextra/issues/5036).
Remove these overrides after upgrading to a fixed Nextra release and checking
all pages, including the 404 page. Development uses Webpack to avoid the current
Turbopack MDX import-alias failure in this monorepo.

Before updating public claims, check authenticated repository visibility,
unauthenticated npm access and clean installation, the deployment manifest and
actual testnet bytecode. Source features, published packages, deployed contracts
and planned work are separate states. Audit, performance, interoperability and
regulatory claims require their own evidence.
