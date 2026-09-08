import { describe, expect, it } from 'vitest';
import { getRecipe, getSignal, getTopic, listRecipes, listSignals, listTopics } from '@clearproof/content';
import { GET as manifest } from '../app/api/content/manifest/route';
import { GET as topic } from '../app/api/content/topics/[slug]/route';
import { GET as recipe } from '../app/api/content/recipes/[slug]/route';
import { GET as signal } from '../app/api/content/signals/[slug]/route';

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
