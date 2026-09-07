import { Readable } from 'node:stream';
export { reportEndpoint, requestReport } from '@clearproof/proof';
export type { ReportPath } from '@clearproof/proof';

const INPUT_LIMIT = 1024 * 1024;

export async function readPrivateInput(input: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  const timeout = setTimeout(() => input.destroy(new Error('Input timeout')), 10_000);
  try {
    for await (const chunk of input) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > INPUT_LIMIT) throw new Error('Input limit exceeded');
      chunks.push(bytes);
    }
    if (!size) throw new Error('Empty input');
    return Buffer.concat(chunks);
  } finally {
    clearTimeout(timeout);
  }
}
