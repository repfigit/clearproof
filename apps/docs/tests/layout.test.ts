import { createElement } from 'react';
import { beforeEach, expect, it, vi } from 'vitest';

const dependencies = vi.hoisted(() => ({ pageMap: vi.fn(), mdxComponents: vi.fn() }));

// Nextra supplies framework rendering. These tests cover the authored layout's
// composition and error propagation, not Nextra internals or browser hydration.
vi.mock('nextra-theme-docs', () => ({
  Layout: 'section', Navbar: 'nav', Footer: 'footer',
  useMDXComponents: dependencies.mdxComponents,
}));
vi.mock('nextra/components', () => ({ Head: 'head' }));
vi.mock('nextra/page-map', () => ({ getPageMap: dependencies.pageMap }));
vi.mock('nextra-theme-docs/style.css', () => ({}));
vi.mock('@vercel/analytics/next', () => ({ Analytics: 'span' }));

import RootLayout, { metadata } from '../app/layout';
import { useMDXComponents } from '../mdx-components';

beforeEach(() => vi.resetAllMocks());

// VERCEL=1 is set on real Vercel deployments only: there the edge serves
// /_vercel/insights/script.js. Elsewhere (self-hosted `next start`, e2e
// webServer, CI) rendering <Analytics /> would just 404 on every page load,
// so the layout renders nothing and the tests below pin both branches.
async function renderBody(children: React.ReactNode) {
  const html = await RootLayout({ children });
  return html.props.children.find((child: React.ReactNode) => (child as any)?.type === 'body');
}

it('composes the docs shell around page content and the loaded page map', async () => {
  const pageMap = [{ name: 'docs', route: '/docs' }];
  dependencies.pageMap.mockResolvedValue(pageMap);
  const content = createElement('article', null, 'Synthetic page content');
  const body = await renderBody(content);
  const [layout] = body.props.children;
  expect(layout.props.children).toBe(content);
  expect(layout.props.pageMap).toBe(pageMap);
  expect(layout.props.editLink).toBeNull();
  expect(layout.props.feedback).toEqual({ content: null });
  expect(layout.props.navbar.props.children.props.href).toBe('https://clearproof.world');
  expect(layout.props.navbar.props.logo.props.children[0].props).toMatchObject({
    src: '/logo.png', alt: '', width: 28, height: 28,
  });
  const footerChildren = layout.props.footer.props.children;
  expect(footerChildren.filter((child: unknown) => typeof child !== 'object').join('')).toBe(`Apache-2.0 ${new Date().getFullYear()} © clearproof contributors · `);
  expect(footerChildren.at(-1).props).toMatchObject({ href: '/docs/report-issues', children: 'Report an issue' });
  expect(metadata.title).toEqual({ template: '%s | clearproof docs', default: 'clearproof docs' });
  expect(metadata.description).toContain('pilot-stage');
  expect(dependencies.pageMap).toHaveBeenCalledExactlyOnceWith();
});

it('renders Analytics on Vercel deployments (VERCEL=1) and omits it elsewhere', async () => {
  const pageMap = [{ name: 'docs', route: '/docs' }];
  dependencies.pageMap.mockResolvedValue(pageMap);
  const content = createElement('article', null, 'Synthetic page content');

  vi.stubEnv('VERCEL', '1');
  const onVercel = await renderBody(content);
  const onVercelChildren = onVercel.props.children;
  expect(onVercelChildren).toHaveLength(2);
  const [layoutOn, analytics] = onVercelChildren;
  expect(layoutOn.type).toBe('section');
  expect(layoutOn.props.children).toBe(content);
  expect(analytics.type).toBe('span');

  vi.stubEnv('VERCEL', '');
  const selfHosted = await renderBody(content);
  const selfHostedChildren = selfHosted.props.children;
  expect(selfHostedChildren).toHaveLength(2);
  const [layoutOff, analyticsOff] = selfHostedChildren;
  expect(layoutOff.type).toBe('section');
  expect(layoutOff.props.children).toBe(content);
  expect(analyticsOff).toBeNull();

  vi.unstubAllEnvs();
});

it('propagates page-map loading failure instead of returning an incomplete shell', async () => {
  const failure = new Error('Synthetic page-map failure');
  dependencies.pageMap.mockRejectedValue(failure);
  await expect(RootLayout({ children: 'Synthetic content' })).rejects.toBe(failure);
});

it('passes custom MDX components to the theme and preserves the returned registry', () => {
  const overrides = { h1: 'h2' };
  const resolved = { h1: 'h2', p: 'p' };
  dependencies.mdxComponents.mockReturnValue(resolved);
  expect(useMDXComponents(overrides)).toBe(resolved);
  expect(dependencies.mdxComponents).toHaveBeenCalledExactlyOnceWith(overrides);
});
