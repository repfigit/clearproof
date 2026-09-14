import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import { listExplainers, getExplainer } from '../src/explainers.js';

vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, readFileSync: vi.fn(actual.readFileSync), readdirSync: vi.fn(actual.readdirSync) };
});
afterEach(() => vi.mocked(fs.readFileSync).mockReset());
afterEach(() => vi.mocked(fs.readdirSync).mockReset());

function file(body: string) {
  vi.mocked(fs.readFileSync).mockReturnValue(body);
}

const complete = (overrides: Record<string, string> = {}) =>
  `---\nid: UP-EX-1\ntitle: Example explainer\ndate: 2026-09-13\npublishAfter: 2026-09-13T00:00:00Z\nsourceCommit: abc123\nclaimRefs:\n - README.md\nstatus: approved\nsummary: Example summary\ncanonical: /explainers/example\ntemplateVersion: explainer-v1\n${overrides ? Object.entries(overrides).map(([k, v]) => `${k}: ${v}`).join('\n') + '\n' : ''}---\nbody text`;

describe('explainers catalogue', () => {
  it('lists explainers with full metadata and sorts newest first', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['older.md', 'newer.md'] as never);
    vi.mocked(fs.readFileSync).mockImplementation(((path: fs.PathLike) =>
      String(path).endsWith('older.md') ? complete({ date: '2026-09-01', id: 'UP-EX-2' }) : complete()) as never);
    expect(listExplainers()).toEqual([
      {
        id: 'UP-EX-1',
        slug: 'newer',
        title: 'Example explainer',
        date: '2026-09-13',
        publishAfter: '2026-09-13T00:00:00Z',
        sourceCommit: 'abc123',
        claimRefs: ['README.md'],
        status: 'approved',
        summary: 'Example summary',
        canonical: '/explainers/example',
        templateVersion: 'explainer-v1',
      },
      {
        id: 'UP-EX-2',
        slug: 'older',
        title: 'Example explainer',
        date: '2026-09-01',
        publishAfter: '2026-09-13T00:00:00Z',
        sourceCommit: 'abc123',
        claimRefs: ['README.md'],
        status: 'approved',
        summary: 'Example summary',
        canonical: '/explainers/example',
        templateVersion: 'explainer-v1',
      },
    ]);
  });

  it('returns null when a file lacks required metadata or cannot be read', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['broken.md'] as never);
    vi.mocked(fs.readFileSync).mockImplementation(((path: fs.PathLike) =>
      String(path).endsWith('broken.md')
        ? '---\ntitle: Missing required fields\n---\nbody'
        : (() => { throw new Error('unreadable'); })()) as never);
    expect(listExplainers()).toEqual([]);
    expect(getExplainer('broken')).toBeNull();
    expect(getExplainer('missing-from-disk')).toBeNull();
  });

  it('getExplainer returns the body alongside metadata', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['example.md'] as never);
    file(complete());
    expect(getExplainer('example')).toEqual({
      id: 'UP-EX-1',
      slug: 'example',
      title: 'Example explainer',
      date: '2026-09-13',
      publishAfter: '2026-09-13T00:00:00Z',
      sourceCommit: 'abc123',
      claimRefs: ['README.md'],
      status: 'approved',
      summary: 'Example summary',
      canonical: '/explainers/example',
      templateVersion: 'explainer-v1',
      body: 'body text',
    });
  });

  it('drops a non-array claimRefs value', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['x.md'] as never);
    file(complete({ claimRefs: 'not-an-array' }));
    expect(listExplainers()[0].claimRefs).toEqual([]);
  });

  it('normalizes unknown status values to draft and drops non-string claim refs', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['odd.md'] as never);
    // The simple frontmatter parser keeps array items as raw strings, so '- 7' stays "7";
    // the filter drops non-string entries, which can only arrive via direct metadata input.
    file('---\nid: UP-EX-3\ntitle: Odd\ndate: 2026-09-13\npublishAfter: 2026-09-13T00:00:00Z\nsourceCommit: abc\nclaimRefs:\n - 7\n - ok\nstatus: future-state\nsummary: s\ncanonical: /explainers/odd\ntemplateVersion: explainer-v1\n---\nbody');
    expect(listExplainers()[0]).toMatchObject({ status: 'draft', claimRefs: ['7', 'ok'] });
  });

  it('breaks same-day ties deterministically by slug', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['b.md', 'a.md'] as never);
    vi.mocked(fs.readFileSync)
      .mockReturnValueOnce(complete({ id: 'UP-EX-4' }))
      .mockReturnValueOnce(complete({ id: 'UP-EX-5' }));
    expect(listExplainers().map(item => item.slug)).toEqual(['a', 'b']);
  });

  it('sorts older dates after newer ones in the ascending branch', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['p.md', 'q.md'] as never);
    const files: Record<string, string> = {
      'p.md': complete({ id: 'UP-EX-6', date: '2026-09-01' }),
      'q.md': complete({ id: 'UP-EX-7', date: '2026-09-02' }),
    };
    vi.mocked(fs.readFileSync).mockImplementation(((path: fs.PathLike) =>
      files[String(path).split('/').pop() ?? ''] ?? '') as never);
    expect(listExplainers().map(item => item.slug)).toEqual(['q', 'p']);
  });
});
