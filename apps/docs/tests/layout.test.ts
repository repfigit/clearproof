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

import RootLayout, { metadata } from '../app/layout';
import { useMDXComponents } from '../mdx-components';

beforeEach(() => vi.resetAllMocks());

it('composes the docs shell around page content and the loaded page map', async () => {
  const pageMap = [{ name: 'docs', route: '/docs' }];
  dependencies.pageMap.mockResolvedValue(pageMap);
  const content = createElement('article', null, 'Synthetic page content');
  const html = await RootLayout({ children: content });
  expect(html.type).toBe('html');
  expect(html.props).toMatchObject({ lang: 'en', dir: 'ltr', suppressHydrationWarning: true });
  const [head, body] = html.props.children;
  expect(head.type).toBe('head');
  expect(body.type).toBe('body');
  const layout = body.props.children;
  expect(layout.props.children).toBe(content);
  expect(layout.props.pageMap).toBe(pageMap);
  expect(layout.props.editLink).toBeNull();
  expect(layout.props.feedback).toEqual({ content: null });
  expect(layout.props.navbar.props.children.props.href).toBe('https://clearproof.world');
  expect(layout.props.navbar.props.logo.props.children[0].props).toMatchObject({
    src: '/logo.png', alt: '', width: 28, height: 28,
  });
  expect(layout.props.footer.props.children.join('')).toBe(`Apache-2.0 ${new Date().getFullYear()} © clearproof contributors`);
  expect(metadata.title).toEqual({ template: '%s | clearproof docs', default: 'clearproof docs' });
  expect(metadata.description).toContain('pilot-stage');
  expect(dependencies.pageMap).toHaveBeenCalledExactlyOnceWith();
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
