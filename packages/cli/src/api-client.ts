import { Readable } from 'node:stream';

const INPUT_LIMIT = 1024 * 1024;
const OUTPUT_LIMIT = 2 * 1024 * 1024;

export type ReportPath = '/pilot/policy/diff' | '/pilot/policy/diff/stored' | '/pilot/events/investigate' | '/pilot/events/queue';

export function reportEndpoint(base: string, path: ReportPath): URL {
  const url = new URL(base);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw new Error('Invalid API origin');
  }
  url.pathname = path;
  return url;
}

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

export async function requestReport(base: string, token: string, path: ReportPath, input: Buffer, signal?: AbortSignal): Promise<Record<string, unknown>> {
  if (!token || /[\s\x00-\x1f\x7f]/.test(token) || input.length === 0 || input.length > INPUT_LIMIT) {
    throw new Error('Invalid comparison configuration');
  }
  const response = await fetch(reportEndpoint(base, path), {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: new Uint8Array(input),
    redirect: 'error',
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000),
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new Error('Comparison request rejected');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > OUTPUT_LIMIT) throw new Error('Response limit exceeded');
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  const report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('Invalid report');
  return report as Record<string, unknown>;
}
