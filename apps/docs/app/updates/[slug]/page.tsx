import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Markdown } from '../../components/markdown';
import { getUpdate, listUpdates } from '@clearproof/content';
import { gatedVisible, visibleUpdates } from '../../../src/feed';

// Pause switch must be evaluated per request, not frozen at build time.
export const dynamic = 'force-dynamic';

export async function generateStaticParams() {
  return gatedVisible(visibleUpdates(listUpdates().map(update => getUpdate(update.slug)).filter(update => update !== null))).map(
    update => ({ slug: update.slug }),
  );
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const update = gatedVisible(visibleUpdates(
    listUpdates().map(item => getUpdate(item.slug)).filter(item => item !== null),
  )).find(item => item.slug === slug);
  if (!update) return { title: 'Update not found — clearproof' };
  return { title: `${update.title} — clearproof`, description: update.summary, alternates: { canonical: `/updates/${update.slug}` } };
}

export default async function UpdatePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const updates = gatedVisible(
    visibleUpdates(listUpdates().map(item => getUpdate(item.slug)).filter(item => item !== null)),
  );
  const update = updates.find(item => item.slug === slug);
  if (!update) notFound();

  return (
    <main className="x:mx-auto x:w-full x:max-w-(--nextra-content-width) x:px-4 x:py-12">
      <nav className="x:text-sm">
        <Link className="x:underline" href="/updates">← All updates</Link>
      </nav>
      <h1 className="x:mt-8 x:text-3xl x:font-bold x:tracking-tight">{update.title}</h1>
      <div className="x:mt-2 x:text-sm x:text-gray-400">
        {update.date} · {update.status} · source revision <code>{update.sourceCommit.slice(0, 12)}</code>
      </div>
      <p className="x:mt-2 x:text-sm x:text-gray-400">{update.summary}</p>
      <div className="x:mt-8 x:text-gray-800 x:dark:text-gray-200">
        <Markdown>{update.body}</Markdown>
      </div>
      {update.claimRefs.length > 0 && (
        <div className="x:mt-8 x:border-t x:pt-4 x:text-sm x:text-gray-400">
          Claim references checked against{' '}
          <code>{update.sourceCommit.slice(0, 12)}</code>:{' '}
          {update.claimRefs.map((ref, index) => (
            <span key={ref}>
              {index > 0 && ', '}
              <code>{ref}</code>
            </span>
          ))}
        </div>
      )}
    </main>
  );
}
