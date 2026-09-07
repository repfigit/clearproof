import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import { join } from 'node:path';
import { CONTENT_DIR, parseFrontmatter, readContentFile, listContentSlugs } from '../src/parser.js';
import { getTopic, listTopics } from '../src/topics.js';
import { getRecipe, getRecipeSteps, listRecipes } from '../src/recipes.js';
import { getSignal, listSignals } from '../src/signals.js';

vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, readFileSync: vi.fn(actual.readFileSync), readdirSync: vi.fn(actual.readdirSync) };
});
afterEach(() => vi.mocked(fs.readFileSync).mockReset());
afterEach(() => vi.mocked(fs.readdirSync).mockReset());

function file(body: string) {
  vi.mocked(fs.readFileSync).mockReturnValue(body);
}

describe('frontmatter syntax', () => {
  it('preserves markdown without a complete frontmatter block', () => {
    for (const raw of ['# Heading\nbody', '---\nunfinished', '']) {
      expect(parseFrontmatter(raw)).toEqual({ frontmatter: {}, body: raw });
    }
  });
  it('parses supported scalars, arrays, blank lines and CRLF delimiters', () => {
    const raw = '---\r\ntitle: Example\r\ncount: 12\r\nenabled: true\r\ndisabled: false\r\n' +
      'prereqs:\r\n - node\r\n - python\r\n# ignored\r\nlast:\r\n - item\r\n---\r\n  Body  ';
    expect(parseFrontmatter(raw)).toEqual({ frontmatter: {
      title: 'Example', count: 12, enabled: true, disabled: false, prereqs: ['node', 'python'], last: ['item'],
    }, body: 'Body' });
  });
  it('handles empty arrays and ignores orphan list entries', () => {
    expect(parseFrontmatter('---\n- orphan\nempty:\nnext: value\ntrailing:\n---\n').frontmatter)
      .toEqual({ empty: [], next: 'value', trailing: [] });
  });
});

describe('content files and topic catalogue', () => {
  it('reads from the packaged content root and sorts only markdown slugs', () => {
    file('---\ntitle: Test\n---\nbody');
    expect(readContentFile('topics/test.md').body).toBe('body');
    expect(fs.readFileSync).toHaveBeenCalledWith(join(CONTENT_DIR, 'topics/test.md'), 'utf-8');
    vi.mocked(fs.readdirSync).mockReturnValue(['z.md', 'notes.txt', 'a.md'] as never);
    expect(listContentSlugs('topics')).toEqual(['a', 'z']);
    vi.mocked(fs.readdirSync).mockImplementationOnce(() => { throw new Error('missing directory'); });
    expect(listContentSlugs('missing')).toEqual([]);
  });
  it('orders topics by metadata and supplies documented defaults', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['fallback.md', 'first.md'] as never);
    vi.mocked(fs.readFileSync).mockReturnValueOnce('body').mockReturnValueOnce(
      '---\ntitle: First\ncategory: start\norder: 1\n---\ntext');
    expect(listTopics()).toEqual([
      { slug: 'first', title: 'First', category: 'start', order: 1 },
      { slug: 'fallback', title: 'fallback', category: 'general', order: 999 },
    ]);
    file('body');
    expect(getTopic('fallback')).toEqual({ slug: 'fallback', title: 'fallback', category: 'general', order: 999, body: 'body' });
    file('---\ntitle: First\ncategory: start\norder: 1\n---\ntext');
    expect(getTopic('first')).toEqual({ slug: 'first', title: 'First', category: 'start', order: 1, body: 'text' });
    vi.mocked(fs.readFileSync).mockImplementationOnce(() => { throw new Error('not found'); });
    expect(getTopic('missing')).toBeNull();
  });
});

describe('recipe metadata and executable steps', () => {
  it('loads recipe metadata with and without optional fields', () => {
    vi.mocked(fs.readdirSync).mockReturnValue(['a.md', 'b.md'] as never);
    vi.mocked(fs.readFileSync).mockReturnValueOnce('body').mockReturnValueOnce(
      '---\ntitle: Named\nprereqs:\n - node\nestimated-time: 5m\n---\nbody');
    expect(listRecipes()).toEqual([
      { slug: 'a', title: 'a', prereqs: [], estimatedTime: 'unknown' },
      { slug: 'b', title: 'Named', prereqs: ['node'], estimatedTime: '5m' },
    ]);
  });
  it('extracts multiple commands and expected output without executing them', () => {
    file('---\ntitle: Sample\nprereqs:\n - node\nestimated-time: 5m\n---\n' +
      '# First step\n\n```bash:run\necho one\necho two\n```\n\nExpected: two\n' +
      '## Second step\n```bash:run\necho three\n```\nOrdinary prose');
    const recipe = getRecipe('sample')!;
    expect(recipe.title).toBe('Sample');
    expect(recipe.prereqs).toEqual(['node']);
    expect(recipe.estimatedTime).toBe('5m');
    expect(recipe.steps).toEqual([
      { description: 'First step', command: 'echo one\necho two', expected: 'two' },
      { description: 'Second step', command: 'echo three', expected: '' },
    ]);
    expect(getRecipeSteps('sample')).toEqual(recipe.steps);
  });
  it('handles no heading, missing closing fence, and missing recipes', () => {
    file('```bash:run\necho unfinished');
    expect(getRecipe('minimal')).toEqual({ slug: 'minimal', title: 'minimal', prereqs: [], estimatedTime: 'unknown',
      body: '```bash:run\necho unfinished', steps: [{ description: '', command: 'echo unfinished', expected: '' }] });
    file('prose without a command');
    expect(getRecipeSteps('prose')).toEqual([]);
    vi.mocked(fs.readFileSync).mockImplementation(() => { throw new Error('missing'); });
    expect(getRecipe('missing')).toBeNull();
    expect(getRecipeSteps('missing')).toEqual([]);
  });
});

describe('signal catalogue', () => {
  it('reads YAML signals, looks up names and handles absent lists', () => {
    file('signals:\n - index: 0\n   name: is_compliant\n   isOutput: true\n');
    expect(listSignals()).toEqual([{ index: 0, name: 'is_compliant', isOutput: true }]);
    expect(getSignal('is_compliant')?.index).toBe(0);
    expect(getSignal('unknown')).toBeNull();
    file('metadata: empty');
    expect(listSignals()).toEqual([]);
  });
});
