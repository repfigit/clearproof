import { describe, expect, it } from 'vitest';
import type { Update } from '@clearproof/content';
import { buildFeedXml, buildSitemapXml, visibleUpdates } from '../src/feed';

const NOW = new Date('2026-09-09T12:00:00Z');

function update(overrides: Partial<Update> = {}): Update {
  return {
    id: 'UP-1',
    slug: 'example-update',
    title: 'Example update',
    date: '2026-09-09',
    publishAfter: '2026-09-09T00:00:00Z',
    sourceCommit: 'abc123',
    claimRefs: ['docs/ADOPTION_ROADMAP.md'],
    status: 'approved',
    summary: 'Example summary',
    body: 'First paragraph with [a link](https://example.com) and `code`.\n\n```js\nhidden();\n```',
    ...overrides,
  };
}

describe('visibleUpdates', () => {
  it('keeps approved and published updates whose publishAfter has passed', () => {
    const updates = [
      update({ slug: 'approved', status: 'approved' }),
      update({ slug: 'published', status: 'published' }),
      update({ slug: 'draft', status: 'draft' }),
      update({ slug: 'validated', status: 'validated' }),
      update({ slug: 'future', publishAfter: '2026-09-10T00:00:00Z' }),
      update({ slug: 'invalid-date', publishAfter: 'not-a-date' }),
    ];
    expect(visibleUpdates(updates, NOW).map(item => item.slug)).toEqual(['approved', 'published']);
  });
});

describe('buildFeedXml', () => {
  it('renders valid RSS 2.0 with escaped XML and absolute links', () => {
    const xml = buildFeedXml([update({ title: 'Quotes & <angles>' })], NOW);
    expect(xml).toContain('<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">');
    expect(xml).toContain('<title>Quotes &amp; &lt;angles&gt;</title>');
    expect(xml).toContain('<link>https://www.clearproof.world/updates/example-update</link>');
    expect(xml).toContain('<guid isPermaLink="true">https://www.clearproof.world/updates/example-update</guid>');
    expect(xml).toContain('<pubDate>Wed, 09 Sep 2026 00:00:00 GMT</pubDate>');
    // Link text survives; code fences do not leak into the description.
    expect(xml).toContain('First paragraph with a link and code.');
    expect(xml).not.toContain('hidden()');
    expect(xml).toContain('<atom:link href="https://www.clearproof.world/feed.xml"');
  });

  it('respects the feed limit and hides invisible updates entirely', () => {
    const many = Array.from({ length: 25 }, (_, index) =>
      update({ slug: `update-${index}`, id: `UP-${index}`, title: `Update ${index}`, date: '2026-09-01' }),
    );
    const xml = buildFeedXml([...many, update({ slug: 'draft', status: 'draft' })], NOW);
    expect((xml.match(/<item>/g) ?? []).length).toBe(20);
    expect(xml).not.toContain('draft');
  });

  it('produces an empty channel when nothing is visible', () => {
    const xml = buildFeedXml([], NOW);
    expect(xml).toContain('<rss version="2.0"');
    expect(xml).not.toContain('<item>');
  });
});

describe('buildSitemapXml', () => {
  it('lists home, updates index and each visible update with lastmod dates', () => {
    const xml = buildSitemapXml(
      [update({ slug: 'a', date: '2026-09-09' }), update({ slug: 'b', date: '2026-09-08' })],
      NOW,
    );
    expect(xml).toContain('http://www.sitemaps.org/schemas/sitemap/0.9');
    expect(xml).toContain('<loc>https://www.clearproof.world/</loc>');
    expect(xml).toContain('<loc>https://www.clearproof.world/updates</loc><lastmod>2026-09-09</lastmod>');
    expect(xml).toContain('<loc>https://www.clearproof.world/updates/a</loc><lastmod>2026-09-09</lastmod>');
    expect(xml).toContain('<loc>https://www.clearproof.world/updates/b</loc><lastmod>2026-09-08</lastmod>');
    expect(xml).not.toContain('/updates/draft');
  });
});
