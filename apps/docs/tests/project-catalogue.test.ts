import { afterEach, expect, it, vi } from 'vitest';
import { getExplainer, listExplainers, PROJECT_STATUS } from '@clearproof/content';
import { GET, dynamic } from '../app/api/content/project/route';

afterEach(() => { vi.useRealTimers(); delete process.env.PUBLISHING_ENABLED; });

it('serves release facts and only articles that are publicly visible at the request clock', async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-10-05T12:00:00Z'));
  const response = await GET();
  expect(dynamic).toBe('force-dynamic');
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('public, max-age=300');
  const catalogue = await response.json();
  expect(catalogue).toMatchObject(PROJECT_STATUS);
  const expected = listExplainers().map(item => getExplainer(item.slug)).filter(item => item !== null)
    .filter(item => ['approved', 'published'].includes(item.status) && Date.parse(item.publishAfter) <= Date.now())
    .map(({ slug, title, publishAfter }) => ({ slug, title, publishAfter }));
  expect(catalogue.explainers).toEqual(expected);
  expect(catalogue.explainers.map((item: { slug: string }) => item.slug)).not.toContain('investigating-missing-information');
  expect(catalogue.explainers.map((item: { slug: string }) => item.slug)).not.toContain('what-the-proof-does-not-check');
  vi.setSystemTime(new Date('2026-10-13T00:00:00Z'));
  expect((await (await GET()).json()).explainers.map((item: { slug: string }) => item.slug))
    .toContain('what-the-proof-does-not-check');
});

it('retains factual release status while a publication pause hides all promoted articles', async () => {
  process.env.PUBLISHING_ENABLED = 'off';
  expect(await (await GET()).json()).toEqual({ ...PROJECT_STATUS, explainers: [] });
});
