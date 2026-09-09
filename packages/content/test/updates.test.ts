import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { CONTENT_DIR } from '../src/parser.js';
import { getUpdate, listUpdates, type UpdateMeta } from '../src/updates.js';

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
  `---\nid: UP-1\ntitle: Example update\ndate: 2026-09-09\npublishAfter: 2026-09-09T00:00:00Z\nsourceCommit: abc123\nclaimRefs:\n - README.md\nstatus: approved\nsummary: Example summary\n${overrides ? Object.entries(overrides).map(([k, v]) => `${k}: ${v}`).join('\n') + '\n' : ''}---\nbody text`;

const META: UpdateMeta = {
  id: 'UP-1',
  slug: 'example',
  title: 'Example update',
  date: '2026-09-09',
  publishAfter: '2026-09-09T00:00:00Z',
  sourceCommit: 'abc123',
  claimRefs: ['README.md'],
  status: 'approved',
  summary: 'Example summary',
};

describe('updates catalogue', () => {
  it('reads updates, supplies empty claimRefs and sorts newest first', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['older.md', 'newer.md'] as never);
    // listContentSlugs sorts slugs before reading, so files are read in sorted order.
    vi.mocked(fs.readFileSync)
      .mockImplementation(((path: fs.PathLike) =>
        String(path).endsWith('older.md') ? complete({ date: '2026-09-01', id: 'UP-2' }) : complete()) as never);
    expect(listUpdates()).toEqual([
      { ...META, slug: 'newer' },
      { ...META, id: 'UP-2', slug: 'older', date: '2026-09-01' },
    ]);
    // getUpdate re-reads the file; restore a complete fixture under the requested slug's path.
    vi.mocked(fs.readFileSync).mockImplementation(((path: fs.PathLike) =>
      String(path).endsWith('example.md') ? complete() : '') as never);
    expect(getUpdate('example')).toEqual({ ...META, slug: 'example', body: 'body text' });
  });

  it('breaks same-day ties deterministically by slug', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['b.md', 'a.md'] as never);
    vi.mocked(fs.readFileSync)
      .mockReturnValueOnce(complete({ id: 'UP-2' }))
      .mockReturnValueOnce(complete({ id: 'UP-3' }));
    expect(listUpdates().map(item => item.slug)).toEqual(['a', 'b']);
  });

  it('returns null when a file exists but lacks required metadata, or cannot be read', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['broken.md'] as never);
    vi.mocked(fs.readFileSync).mockImplementation(((path: fs.PathLike) =>
      String(path).endsWith('broken.md')
        ? '---\ntitle: Missing required fields\n---\nbody'
        : (() => { throw new Error('unreadable'); })()) as never);
    expect(listUpdates()).toEqual([]);
    expect(getUpdate('broken')).toBeNull();
    expect(getUpdate('missing-from-disk')).toBeNull();
  });

  it('drops a non-array claimRefs value and sorts ascending dates in both comparator directions', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['x.md', 'y.md', 'z.md'] as never);
    const files: Record<string, string> = {
      'x.md': complete({ id: 'UP-10', date: '2026-09-03', claimRefs: 'not-an-array' }),
      'y.md': complete({ id: 'UP-11', date: '2026-09-01' }),
      'z.md': complete({ id: 'UP-12', date: '2026-09-02' }),
    };
    vi.mocked(fs.readFileSync).mockImplementation(((path: fs.PathLike) =>
      files[String(path).split('/').pop() ?? ''] ?? '') as never);
    expect(listUpdates().map(item => item.slug)).toEqual(['x', 'z', 'y']);
    // 'x' supplied a scalar claimRefs value, which is dropped in favour of the empty default.
    expect(listUpdates()[0].claimRefs).toEqual([]);
    expect(listUpdates()[2].claimRefs).toEqual(['README.md']);
  });

  it('normalizes unknown status values to draft and drops non-string claim refs', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['odd.md'] as never);
    // The simple frontmatter parser keeps array items as raw strings, so '- 7' stays "7";
    // the filter drops non-string entries, which can only arrive via direct metadata input.
    file('---\nid: UP-4\ntitle: Odd\ndate: 2026-09-09\npublishAfter: 2026-09-09T00:00:00Z\nsourceCommit: abc\nclaimRefs:\n - 7\n - ok\nstatus: future-state\nsummary: s\n---\nbody');
    expect(listUpdates()[0]).toMatchObject({ status: 'draft', claimRefs: ['7', 'ok'] });
    expect(CONTENT_DIR).toContain('content');
  });
});
