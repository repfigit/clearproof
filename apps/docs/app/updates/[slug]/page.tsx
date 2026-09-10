import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getUpdate, listUpdates } from '@clearproof/content';
import { visibleUpdates } from '../../../src/feed';

export async function generateStaticParams() {
  return visibleUpdates(listUpdates().map(update => getUpdate(update.slug)).filter(update => update !== null)).map(
    update => ({ slug: update.slug }),
  );
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const update = visibleUpdates(
    listUpdates().map(item => getUpdate(item.slug)).filter(item => item !== null),
  ).find(item => item.slug === slug);
  if (!update) return { title: 'Update not found — clearproof' };
  return { title: `${update.title} — clearproof`, description: update.summary };
}

export default async function UpdatePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const updates = visibleUpdates(
    listUpdates().map(item => getUpdate(item.slug)).filter(item => item !== null),
  );
  const update = updates.find(item => item.slug === slug);
  if (!update) notFound();

  const bodyParagraphs = update.body
    .split(/\n{2,}/)
    .map(paragraph => paragraph.trim())
    .filter(Boolean);

  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-16">
      <nav className="text-sm">
        <Link className="underline" href="/updates">← All updates</Link>
      </nav>
      <h1 className="mt-6 text-3xl font-bold tracking-tight">{update.title}</h1>
      <div className="mt-2 text-sm text-gray-500">
        {update.date} · {update.status} · source revision <code>{update.sourceCommit.slice(0, 12)}</code>
      </div>
      <p className="mt-2 text-sm text-gray-500">{update.summary}</p>
      <div className="mt-8 space-y-4 text-gray-800 dark:text-gray-200">
        {bodyParagraphs.map((paragraph, index) => (
          <p key={index} className="whitespace-pre-line">{paragraph}</p>
        ))}
      </div>
      {update.claimRefs.length > 0 && (
        <div className="mt-8 border-t pt-4 text-sm text-gray-500">
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
