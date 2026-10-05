import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { DOCUMENTATION_PAGES, documentationMetadata } from '../src/documentation';
import { buildSitemapXml } from '../src/feed';

it('covers every technical documentation page with distinct descriptions and canonical URLs', () => {
  const docs = resolve(import.meta.dirname, '../app/docs');
  const routes = ['/docs', ...readdirSync(docs, { withFileTypes: true })
    .filter(entry => entry.isDirectory()).map(entry => `/docs/${entry.name}`)];
  expect(DOCUMENTATION_PAGES.map(page => page.path).filter(path => path.startsWith('/docs')).sort())
    .toEqual(routes.sort());
  expect(new Set(DOCUMENTATION_PAGES.map(page => page.description)).size).toBe(DOCUMENTATION_PAGES.length);
  const sitemap = buildSitemapXml([], new Date('2026-10-05T00:00:00Z'));
  for (const page of DOCUMENTATION_PAGES) {
    const source = resolve(import.meta.dirname, `../app${page.path === '/' ? '' : page.path}/page.mdx`);
    const exported = /export const metadata = (\{[\s\S]*?\n\});/.exec(readFileSync(source, 'utf8'));
    expect(exported).not.toBeNull();
    expect(JSON.parse(exported![1])).toEqual(documentationMetadata(page.path));
    expect(documentationMetadata(page.path)).toEqual({
      title: page.title, description: page.description, alternates: { canonical: page.path },
    });
    expect(sitemap).toContain(`<loc>https://docs.clearproof.world${page.path}</loc>`);
  }
  expect(() => documentationMetadata('/missing')).toThrow('Unknown documentation route');
});
