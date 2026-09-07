import nextra from 'nextra';
import path from 'node:path';

const withNextra = nextra({});

export default withNextra({
  reactStrictMode: true,
  // This package resolves its Markdown/YAML assets relative to its compiled module.
  serverExternalPackages: ['@clearproof/content'],
  outputFileTracingRoot: path.join(process.cwd(), '../..'),
  webpack(config, { isServer }) {
    if (isServer) {
      // Next 15's external-package matcher only matches node_modules paths;
      // npm workspaces resolve this package to packages/content instead.
      config.externals = [
        { '@clearproof/content': 'commonjs @clearproof/content' },
        ...(Array.isArray(config.externals) ? config.externals : [config.externals].filter(Boolean)),
      ];
    }
    return config;
  },
});
