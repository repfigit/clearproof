import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { getUpdate, listUpdates, type Update } from '@clearproof/content';

const notFound = vi.hoisted(() =>
  vi.fn(() => {
    throw new Error('not-found');
  }),
);

vi.mock('next/navigation', () => ({ notFound }));

import UpdatePage, { generateMetadata, generateStaticParams } from '../app/updates/[slug]/page';
import UpdatesIndex, { metadata as indexMetadata } from '../app/updates/page';
import robots from '../app/robots';

function visibleUpdates(): Update[] {
  return listUpdates()
    .map(item => getUpdate(item.slug))
    .filter(
      (item): item is Update =>
        item !== null
        && (item.status === 'approved' || item.status === 'published')
        && Date.parse(item.publishAfter) <= Date.now(),
    );
}

function visibleSlugs() {
  return visibleUpdates().map(item => item.slug);
}

beforeEach(() => {
  notFound.mockClear();
});

it('exposes updates metadata', () => {
  expect(indexMetadata).toMatchObject({ title: 'Updates — clearproof' });
});

it('exposes a permissive robots policy pointing at the site sitemap', () => {
  const env = process.env;
  expect(robots()).toEqual({
    rules: [{ userAgent: '*', allow: '/' }],
    sitemap: 'https://www.clearproof.world/sitemap.xml',
  });
  process.env = { ...env, NEXT_PUBLIC_SITE_URL: 'https://clearproof.world/' };
  try {
    expect(robots()).toEqual({
      rules: [{ userAgent: '*', allow: '/' }],
      sitemap: 'https://clearproof.world/sitemap.xml',
    });
  } finally {
    process.env = env;
  }
});

it('renders an index entry for every visible update and no hidden ones', async () => {
  const html = renderToStaticMarkup(await UpdatesIndex());
  for (const update of listUpdates()) {
    expect(html.includes(update.title)).toBe(visibleSlugs().includes(update.slug));
  }
});

it('renders an empty-state notice when no updates are visible', async () => {
  const content = await vi.importActual<typeof import('@clearproof/content')>('@clearproof/content');
  const updates = content.listUpdates();
  vi.doMock('@clearproof/content', () => ({
    ...content,
    listUpdates: () => updates.map(update => ({ ...update, publishAfter: '9999-12-31T00:00:00Z' })),
    getUpdate: (slug: string) => null,
  }));
  try {
    vi.resetModules();
    const { default: EmptyIndex } = await import('../app/updates/page');
    const html = renderToStaticMarkup(await EmptyIndex());
    expect(html).toContain('No updates published yet.');
  } finally {
    vi.doUnmock('@clearproof/content');
    vi.resetModules();
  }
});

describe('update detail page', () => {
  it.each(visibleSlugs())('renders visible update %s with citation footer', async slug => {
    const update = getUpdate(slug)!;
    const html = renderToStaticMarkup(await UpdatePage({ params: Promise.resolve({ slug }) }));
    expect(html).toContain(update.title);
    expect(html).toContain(update.summary);
    expect(html).toContain(update.sourceCommit.slice(0, 12));
    for (const ref of update.claimRefs) expect(html).toContain(ref);
  });

  it('renders metadata for a visible update', async () => {
    const slug = visibleSlugs()[0];
    const update = getUpdate(slug)!;
    const meta = await generateMetadata({ params: Promise.resolve({ slug }) });
    expect(meta).toMatchObject({ title: `${update.title} — clearproof`, description: update.summary });
  });

  it('calls notFound for a hidden or unknown slug', async () => {
    await expect(UpdatePage({ params: Promise.resolve({ slug: 'unknown-hidden' }) })).rejects.toThrow('not-found');
    await expect(generateMetadata({ params: Promise.resolve({ slug: 'unknown' }) })).resolves.toMatchObject({
      title: 'Update not found — clearproof',
    });
    expect(notFound).toHaveBeenCalledTimes(1);
  });

  it('pre-generates exactly the visible slugs', async () => {
    expect(await generateStaticParams()).toEqual(visibleSlugs().map(slug => ({ slug })));
  });
});
