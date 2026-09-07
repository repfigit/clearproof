import nextra from 'nextra';
import path from 'node:path';

const withNextra = nextra({});

export default withNextra({
  reactStrictMode: true,
  // This package resolves its Markdown/YAML assets relative to its compiled module.
  serverExternalPackages: ['@clearproof/content'],
  // Keep the workspace symlink external too: relocating its CommonJS __dirname
  // makes the content routes look for assets beside the generated route bundle.
  webpack(config, { isServer }) {
    if (isServer) {
      config.externals.push({ '@clearproof/content': 'commonjs @clearproof/content' });
    }
    return config;
  },
  outputFileTracingRoot: path.join(process.cwd(), '../..'),
});
