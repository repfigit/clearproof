import nextra from 'nextra';
import path from 'node:path';

const withNextra = nextra({});

export default withNextra({
  reactStrictMode: true,
  // This package resolves its Markdown/YAML assets relative to its compiled module.
  serverExternalPackages: ['@clearproof/content'],
  outputFileTracingRoot: path.join(process.cwd(), '../..'),
});
