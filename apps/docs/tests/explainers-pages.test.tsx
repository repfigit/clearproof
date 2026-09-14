import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { getExplainer, listExplainers, type Explainer } from '@clearproof/content';

const notFound = vi.hoisted(() =>
  vi.fn(() => {
    throw new Error('not-found');
  }),
);

vi.mock('next/navigation', () => ({ notFound }));

import ExplainerPage, { generateMetadata, generateStaticParams } from '../app/explainers/[slug]/page';
import ExplainersIndex, { metadata as indexMetadata } from '../app/explainers/page';

function visibleExplainers(): Explainer[] {
  return listExplainers()
    .map(item => getExplainer(item.slug))
    .filter(
      (item): item is Explainer =>
        item !== null
        && (item.status === 'approved' || item.status === 'published')
        && Date.parse(item.publishAfter) <= Date.now(),
    );
}

function visibleSlugs() {
  return visibleExplainers().map(item => item.slug);
}

beforeEach(() => {
  notFound.mockClear();
});

it('exposes explainers metadata', () => {
  expect(indexMetadata).toMatchObject({ title: 'Explainers — clearproof' });
});

it('renders an index entry for every visible explainer and no hidden ones', async () => {
  const html = renderToStaticMarkup(await ExplainersIndex());
  for (const explainer of listExplainers()) {
    expect(html.includes(explainer.title)).toBe(visibleSlugs().includes(explainer.slug));
  }
});

it('renders an empty-state notice when no explainers are visible', async () => {
  const content = await vi.importActual<typeof import('@clearproof/content')>('@clearproof/content');
  const explainers = content.listExplainers();
  vi.doMock('@clearproof/content', () => ({
    ...content,
    listExplainers: () => explainers.map(explainer => ({ ...explainer, publishAfter: '9999-12-31T00:00:00Z' })),
    getExplainer: (slug: string) => null,
  }));
  try {
    vi.resetModules();
    const { default: EmptyIndex } = await import('../app/explainers/page');
    const html = renderToStaticMarkup(await EmptyIndex());
    expect(html).toContain('No explainers published yet.');
  } finally {
    vi.doUnmock('@clearproof/content');
    vi.resetModules();
  }
});

describe('explainer detail page', () => {
  it.each(visibleSlugs())('renders visible explainer %s with citation footer', async slug => {
    const explainer = getExplainer(slug)!;
    const html = renderToStaticMarkup(await ExplainerPage({ params: Promise.resolve({ slug }) }));
    expect(html).toContain(explainer.title);
    // HTML-escape the summary before matching: React escapes quotes/apostrophes in rendered text.
    expect(html).toContain(explainer.summary.replace(/'/g, '&#x27;'));
    expect(html).toContain(explainer.sourceCommit.slice(0, 12));
    for (const ref of explainer.claimRefs) expect(html).toContain(ref);
  });

  it('renders markdown headings, links and claim references in the body', async () => {
    const slug = visibleSlugs()[0];
    const content = await vi.importActual<typeof import('@clearproof/content')>('@clearproof/content');
    const body = [
      '[Leading link](https://example.com/start) followed by trailing text.',
      'Intro paragraph with an [inline link](https://example.com/inline) and text after.',
      '## A section heading',
      '### A subheading',
      'Paragraph with a [link at the end](https://example.com/end)',
    ].join('\n\n');
    vi.doMock('@clearproof/content', () => ({
      ...content,
      getExplainer: (s: string) => {
        const real = content.getExplainer(s);
        return s === slug && real ? { ...real, body } : real;
      },
    }));
    try {
      vi.resetModules();
      const { default: HeadedPage } = await import('../app/explainers/[slug]/page');
      const html = renderToStaticMarkup(await HeadedPage({ params: Promise.resolve({ slug }) }));
      expect(html).toContain('href="https://example.com/inline"');
      expect(html).toContain('href="https://example.com/end"');
      expect(html).toContain('href="https://example.com/start"');
      expect(html).toContain('followed by trailing text.');
      expect(html).not.toContain('[inline link](https://example.com/inline)');
      expect(html).toContain('A section heading');
      expect(html).toContain('A subheading');
      expect(html).toContain('Intro paragraph with an');
    } finally {
      vi.doUnmock('@clearproof/content');
      vi.resetModules();
    }
  });

  it('renders metadata with a canonical URL for a visible explainer', async () => {
    const slug = visibleSlugs()[0];
    const explainer = getExplainer(slug)!;
    const meta = await generateMetadata({ params: Promise.resolve({ slug }) });
    expect(meta).toMatchObject({
      title: `${explainer.title} — clearproof`,
      description: explainer.summary,
      alternates: { canonical: explainer.canonical },
    });
  });

  it('calls notFound for a hidden or unknown slug', async () => {
    await expect(ExplainerPage({ params: Promise.resolve({ slug: 'unknown-hidden' }) })).rejects.toThrow('not-found');
    await expect(generateMetadata({ params: Promise.resolve({ slug: 'unknown' }) })).resolves.toMatchObject({
      title: 'Explainer not found — clearproof',
    });
    expect(notFound).toHaveBeenCalledTimes(1);
  });

  it('pre-generates exactly the visible slugs', async () => {
    expect(await generateStaticParams()).toEqual(visibleSlugs().map(slug => ({ slug })));
  });
});
