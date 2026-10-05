import { readFileSync, readdirSync } from 'node:fs';
import { resolve, relative, dirname } from 'node:path';
import { test, expect } from '@playwright/test';
import { PROJECT_STATUS, getRecipe, getSignal, getTopic, listRecipes, listSignals, listTopics } from '@clearproof/content';
import { DOCUMENTATION_PAGES } from '../src/documentation';

const app = resolve(__dirname, '../app');
const pages = readdirSync(app, { recursive: true, withFileTypes: true })
  .filter(entry => entry.isFile() && entry.name === 'page.mdx')
  .map(entry => {
    const file = resolve(entry.parentPath, entry.name);
    const heading = /^# (.+)$/m.exec(readFileSync(file, 'utf8'))?.[1];
    if (!heading) throw new Error(`MDX page needs an explicit heading: ${file}`);
    return { route: `/${relative(app, dirname(file)).replaceAll('\\', '/')}`, heading };
  });

for (const { route, heading } of pages) {
  test(`renders ${route} without browser errors`, async ({ page, request }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => {
      if (message.type() === 'error') errors.push(message.text());
    });
    const response = await page.goto(route);
    expect(response?.status()).toBe(200);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(heading);
    await expect(page.getByRole('navigation').first()).toBeVisible();
    await expect(page.locator('footer')).toContainText('clearproof contributors');
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    const document = DOCUMENTATION_PAGES.find(item => item.path === route);
    expect(document).toBeDefined();
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', `https://docs.clearproof.world${route === '/' ? '' : route}`);
    await expect(page.locator('meta[name="description"]')).toHaveAttribute('content', document!.description);
    if (route === '/docs/system-diagram') {
      await expect(page.locator('article svg').filter({ hasText: 'Originating VASP' })).toBeVisible();
    }
    // Clicking a local content link exercises client-side MDX navigation too.
    const localLink = page.locator('article a[href^="/docs"]').first();
    if (await localLink.count()) {
      const target = await localLink.getAttribute('href');
      await localLink.click();
      await expect(page).toHaveURL(new URL(target!, page.url()).href);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    }
    expect(errors).toEqual([]);
    const logo = await request.get('/logo.png');
    expect(logo.status()).toBe(200);
    expect(logo.headers()['content-type']).toContain('image/png');
  });
}

test('hydrated content navigation preserves the client session and supports back', async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => { (window as unknown as Record<string, unknown>).coverageNavigationMarker = true; });
  await page.getByRole('link', { name: 'Development status and next steps', exact: true }).click();
  await expect(page).toHaveURL('/docs/status');
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).coverageNavigationMarker)).toBe(true);
  await page.goBack();
  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('clearproof');
});

test('public project catalogue matches documentation status and published explainer links', async ({ page, request }) => {
  const response = await request.get('/api/content/project');
  expect(response.status()).toBe(200);
  const catalogue = await response.json();
  expect(catalogue).toMatchObject(PROJECT_STATUS);
  await page.goto('/docs/status');
  await expect(page.locator('article')).toContainText(PROJECT_STATUS.npmVersion);
  await expect(page.locator('article')).toContainText(PROJECT_STATUS.capacity);
  const sitemap = await request.get('/sitemap.xml');
  const xml = await sitemap.text();
  for (const document of DOCUMENTATION_PAGES) {
    expect(xml).toContain(`<loc>https://docs.clearproof.world${document.path}</loc>`);
  }
  for (const explainer of catalogue.explainers) {
    expect(Date.parse(explainer.publishAfter)).toBeLessThanOrEqual(Date.now());
    const detail = await request.get(`/explainers/${explainer.slug}`);
    expect(detail.status()).toBe(200);
    expect(await detail.text()).toContain(explainer.title.replaceAll('&', '&amp;'));
  }
});

test('unknown pages render a real 404', async ({ page }) => {
  const response = await page.goto('/missing-coverage-page');
  expect(response?.status()).toBe(404);
  await expect(page.getByText('404', { exact: true })).toBeVisible();
});

test('built server resolves every content asset and bounded missing-entry errors', async ({ request }) => {
  const response = await request.get('/api/content/manifest');
  expect(response.status()).toBe(200);
  expect(response.headers()['cache-control']).toBe('public, max-age=300');
  expect(await response.json()).toEqual({ topics: listTopics(), recipes: listRecipes(), signals: listSignals() });
  const catalogues = [
    { name: 'topics', keys: listTopics().map(item => item.slug), get: getTopic },
    { name: 'recipes', keys: listRecipes().map(item => item.slug), get: getRecipe },
    { name: 'signals', keys: listSignals().map(item => item.name), get: getSignal },
  ];
  for (const catalogue of catalogues) {
    expect(catalogue.keys.length).toBeGreaterThan(0);
    for (const key of catalogue.keys) {
      const entry = await request.get(`/api/content/${catalogue.name}/${key}`);
      expect(entry.status()).toBe(200);
      expect(entry.headers()['content-type']).toContain('application/json');
      expect(await entry.json()).toEqual(catalogue.get(key));
    }
    const missing = await request.get(`/api/content/${catalogue.name}/missing-coverage-entry`);
    expect(missing.status()).toBe(404);
    expect(await missing.json()).toEqual({ error: 'Not found' });
  }
});
