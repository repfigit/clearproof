import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';
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

function renderInlineMarkdown(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const linkPattern = /\[([^\]]+)\]\(([^)]+)\)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  while ((match = linkPattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    nodes.push(
      <a key={key++} className="x:underline" href={match[2]}>
        {match[1]}
      </a>,
    );
    lastIndex = match.index + match[0].length;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes;
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
        {bodyParagraphs.map((paragraph, index) => (
          <p key={index} className="x:not-first:mt-[1.25em] x:leading-7 x:whitespace-pre-wrap">
            {renderInlineMarkdown(paragraph)}
          </p>
        ))}
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
