import { Command } from 'commander';
import { readPrivateInput, reportEndpoint, requestReport } from '../api-client.js';

type ObjectValue = Record<string, unknown>;
function object(value: unknown): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid object');
  return value as ObjectValue;
}
function list(value: unknown, max: number): ObjectValue[] {
  if (!Array.isArray(value) || value.length > max) throw new Error('Invalid list');
  return value.map(object);
}
function integer(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error('Invalid integer');
  return value as number;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || value.length > 256 || /[^\x20-\x7e]/.test(value)) throw new Error('Invalid text');
  return value;
}
function cursor(value: unknown): string | null {
  if (value === null) return null;
  const result = text(value);
  if (!/^[a-f0-9]{64}$/.test(result)) throw new Error('Invalid cursor');
  return result;
}
function providerLines(links: unknown): string[] {
  if (links === undefined) return []; // Earlier v1 responses may omit optional navigation references.
  return list(links, 8).map(link => {
    if (typeof link.url !== 'string' || link.url.length > 2048 || /[^\x21-\x7e]|\\/.test(link.url)) throw new Error('Invalid provider link');
    const url = new URL(link.url);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Invalid provider link');
    return `Provider ${text(link.source_id)} | ${text(link.label)} | ${link.url}`;
  });
}
function findingLines(findings: unknown): string[] {
  return list(findings, 32).map(f => `  ${text(f.reason)} | age ${integer(f.age_seconds)}s | owner ${text(f.owner)} | next ${text(f.next_action)}`);
}

export async function collectQueue(base: string, token: string, input: Buffer, pages: number): Promise<ObjectValue> {
  if (!Number.isSafeInteger(pages) || pages < 1 || pages > 32) throw new Error('Invalid page budget');
  const request = object(JSON.parse(input.toString('utf8')));
  const items: ObjectValue[] = [], times: number[] = [];
  const seen = new Set<string>();
  let after = request.after === undefined ? null : cursor(request.after);
  const startedAfter = after;
  let scanned = 0, fetched = 0;
  const deadline = AbortSignal.timeout(60_000);
  for (let pageIndex = 0; pageIndex < pages; pageIndex++) {
    const page = await requestReport(base, token, '/pilot/events/queue', pageIndex === 0 ? input : Buffer.from(JSON.stringify({ ...request, after })), deadline);
    if (page.schema_version !== 'clearproof-investigation-queue-v1' || page.ordering !== 'scope-pages-age-within-page') {
      throw new Error('Invalid queue schema');
    }
    times.push(integer(page.as_of));
    const count = integer(page.scanned_transfers);
    if (count > 16) throw new Error('Invalid page size');
    scanned += count;
    fetched++;
    for (const item of list(page.items, 16)) {
      const id = cursor(item.scope_digest);
      if (id === null || seen.has(id)) throw new Error('Duplicate or invalid scope');
      seen.add(id);
      integer(item.oldest_age_seconds);
      items.push(item);
    }
    const next = cursor(page.next_cursor);
    if (next !== null && (count === 0 || (after !== null && next <= after))) throw new Error('Nonadvancing cursor');
    after = next;
    if (after === null) break;
  }
  items.sort((a, b) => integer(b.oldest_age_seconds) - integer(a.oldest_age_seconds) ||
    text(a.scope_digest).localeCompare(text(b.scope_digest)));
  return { schema_version: 'clearproof-collected-queue-v1', items, next_cursor: after,
    complete_from_start: startedAfter === null && after === null, started_after: startedAfter,
    page_times: times, pages_fetched: fetched, scanned_transfers: scanned,
    snapshot: 'per-page-observations', ordering: 'age-within-collected-results' };
}

export function renderInvestigation(report: ObjectValue, queue: boolean): string {
  const lines: string[] = [];
  if (queue) {
    lines.push(report.complete_from_start === true ? 'Reached the end of the queue traversal.' : 'Partial queue traversal.');
    lines.push('Pages are separate observations; ordering covers collected results.');
    for (const item of list(report.items, 512)) {
      const scope = object(item.scope);
      lines.push(`Transfer ${text(scope.transfer_id)} | ${text(item.scope_digest)} | oldest ${integer(item.oldest_age_seconds)}s`);
      lines.push(...findingLines(item.findings));
      lines.push(...providerLines(item.provider_links));
    }
    if (report.next_cursor !== null) lines.push(`Continue after: ${text(report.next_cursor)}`);
  } else {
    if (report.schema_version !== 'clearproof-investigation-v1') throw new Error('Invalid investigation schema');
    lines.push(`Transfer scope ${text(report.scope_digest)} | observed at ${integer(report.as_of)}`);
    const states = object(report.states);
    for (const name of ['compliance', 'proof', 'counterparty', 'custody', 'chain', 'evidence']) {
      lines.push(`${name}: ${text(states[name])}`);
    }
    lines.push(...findingLines(report.findings));
    lines.push(...providerLines(report.provider_links));
    for (const event of list(report.timeline, 256)) {
      lines.push(`${integer(event.occurred_at)} | received ${integer(event.ingested_at)} | ${text(event.source_id)} | ${text(event.dimension)}: ${text(event.state)}`);
    }
  }
  return lines.join('\n');
}

export const investigationCommand = new Command('investigation').description('Read tenant-private timelines and ageing queues');
for (const name of ['timeline', 'queue']) {
  investigationCommand.command(name)
    .description(name === 'queue' ? 'Read QueueRequest JSON from stdin and collect bounded pages' : 'Read TransferScope JSON from stdin')
    .requiredOption('--api-url <origin>', 'Operator-selected HTTPS API origin, or local loopback HTTP')
    .option('--json', 'Emit JSON instead of a readable report', false)
    .option('--pages <count>', 'Maximum queue pages to collect (1–32)', '1')
    .action(async (options: { apiUrl: string; json: boolean; pages: string }) => {
      try {
        reportEndpoint(options.apiUrl, '/pilot/events/investigate');
        const token = process.env.CLEARPROOF_API_TOKEN ?? '';
        if (!token) throw new Error('Missing token');
        const input = await readPrivateInput(process.stdin);
        const isQueue = name === 'queue';
        const report = isQueue ? await collectQueue(options.apiUrl, token, input, Number(options.pages)) :
          await requestReport(options.apiUrl, token, '/pilot/events/investigate', input);
        const rendered = renderInvestigation(report, isQueue); // Validate consumed fields even for JSON output.
        process.stdout.write((options.json ? JSON.stringify(report) : rendered) + '\n');
      } catch {
        process.stderr.write('Investigation request failed. Check API origin, token, permissions and input.\n');
        process.exitCode = 1;
      }
    });
}
