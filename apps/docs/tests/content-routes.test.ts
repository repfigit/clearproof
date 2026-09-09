import { describe, expect, it } from 'vitest';
import { getRecipe, getSignal, getTopic, getUpdate, listRecipes, listSignals, listTopics, listUpdates } from '@clearproof/content';
import { GET as manifest } from '../app/api/content/manifest/route';
import { GET as topic } from '../app/api/content/topics/[slug]/route';
import { GET as recipe } from '../app/api/content/recipes/[slug]/route';
import { GET as signal } from '../app/api/content/signals/[slug]/route';
import { GET as updatesManifest } from '../app/api/content/updates/route';
import { GET as update } from '../app/api/content/updates/[slug]/route';
import { GET as feed } from '../app/feed.xml/route';
import { GET as sitemap } from '../app/sitemap.xml/route';

function expectJsonCache(response: Response, status: number) {
  expect(response.status).toBe(status);
  expect(response.headers.get('content-type')).toContain('application/json');
  expect(response.headers.get('cache-control')).toBe('public, max-age=300');
}

it('returns the real content catalogue as cacheable JSON', async () => {
  const response = await manifest();
  expectJsonCache(response, 200);
  const data = await response.json();
  expect(data).toEqual({ topics: listTopics(), recipes: listRecipes(), signals: listSignals() });
  for (const records of Object.values(data)) {
    expect((records as unknown[]).length).toBeGreaterThan(0);
  }
});

describe('updates', () => {
  it('serves the updates catalogue as cacheable JSON', async () => {
    const response = await updatesManifest();
    expectJsonCache(response, 200);
    const data = await response.json();
    expect(data).toEqual({ updates: listUpdates() });
  });

  it('serves a single update as cacheable JSON', async () => {
    const slugs = listUpdates().map(item => item.slug);
    expect(slugs.length).toBeGreaterThan(0);
    for (const slug of slugs) {
      const response = await update(
        new Request(`http://localhost/api/content/updates/${slug}`),
        { params: Promise.resolve({ slug }) },
      );
      expectJsonCache(response, 200);
      expect(await response.json()).toEqual(getUpdate(slug));
    }
  });

  it.each(['missing-update', '../package', '', 'constructor', '__proto__'])(
    'returns a bounded JSON error for unknown update slug %j', async slug => {
      const response = await update(new Request('http://localhost/'), {
        params: Promise.resolve({ slug }),
      });
      expectJsonCache(response, 404);
      expect(await response.json()).toEqual({ error: 'Not found' });
    },
  );

  it('serves an RSS feed covering every public update', async () => {
    const response = await feed();
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/rss+xml');
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    const body = await response.text();
    expect(body).toContain('<?xml');
    expect(body).toContain('<rss');
    expect(body).toContain('</rss>');
    for (const slug of listUpdates().map(item => item.slug)) {
      expect(body).toContain(slug);
    }
  });

  it('serves a sitemap covering every public update', async () => {
    const response = await sitemap();
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/xml');
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    const body = await response.text();
    expect(body).toContain('<?xml');
    expect(body).toContain('<urlset');
    expect(body).toContain('</urlset>');
    for (const slug of listUpdates().map(item => item.slug)) {
      expect(body).toContain(slug);
    }
  });
});

const catalogues = [
  { name: 'topics', handler: topic, slugs: listTopics().map(item => item.slug), get: getTopic },
  { name: 'recipes', handler: recipe, slugs: listRecipes().map(item => item.slug), get: getRecipe },
  { name: 'signals', handler: signal, slugs: listSignals().map(item => item.name), get: getSignal },
];

for (const catalogue of catalogues) {
  describe(catalogue.name, () => {
    it.each(catalogue.slugs)('serves catalogue entry %s', async slug => {
      const response = await catalogue.handler(
        new Request(`http://localhost/api/content/${catalogue.name}/${slug}`),
        { params: Promise.resolve({ slug }) },
      );
      expectJsonCache(response, 200);
      expect(await response.json()).toEqual(catalogue.get(slug));
    });

    it.each(['missing-content-entry', '../package', '', 'constructor', '__proto__'])(
      'returns a bounded JSON error for unknown slug %j', async slug => {
        const response = await catalogue.handler(new Request('http://localhost/'), {
          params: Promise.resolve({ slug }),
        });
        expectJsonCache(response, 404);
        expect(await response.json()).toEqual({ error: 'Not found' });
      },
    );
  });
}
