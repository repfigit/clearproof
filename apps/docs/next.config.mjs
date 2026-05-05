import nextra from 'nextra';
import path from 'node:path';

const withNextra = nextra({});

export default withNextra({
  reactStrictMode: true,
  outputFileTracingRoot: path.join(process.cwd(), '../..'),
});
