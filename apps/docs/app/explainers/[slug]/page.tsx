import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';
import { getExplainer, listExplainers } from '@clearproof/content';
import { gatedVisible, visibleExplainers } from '../../../src/feed';

export async function generateStaticParams() {
  return gatedVisible(visibleExplainers(listExplainers().map(explainer => getExplainer(explainer.slug)).filter(explainer => explainer !== null))).map(
    explainer => ({ slug: explainer.slug }),
  );
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const explainer = gatedVisible(visibleExplainers(
    listExplainers().map(item => getExplainer(item.slug)).filter(item => item !== null),
  )).find(item => item.slug === slug);
  if (!explainer) return { title: 'Explainer not found — clearproof' };
  return {
    title: `${explainer.title} — clearproof`,
    description: explainer.summary,
    alternates: { canonical: explainer.canonical },
  };
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

export default async function ExplainerPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const explainers = gatedVisible(
    visibleExplainers(listExplainers().map(item => getExplainer(item.slug)).filter(item => item !== null)),
  );
  const explainer = explainers.find(item => item.slug === slug);
  if (!explainer) notFound();

  const bodyParagraphs = explainer.body
    .split(/\n{2,}/)
    .map(paragraph => paragraph.trim())
    .filter(Boolean);

  const headingClass = 'x:mt-8 x:text-xl x:font-semibold x:tracking-tight';

  return (
    <main className="x:mx-auto x:w-full x:max-w-(--nextra-content-width) x:px-4 x:py-12">
      <nav className="x:text-sm">
        <Link className="x:underline" href="/explainers">← All explainers</Link>
      </nav>
      <article>
        <h1 className="x:mt-8 x:text-3xl x:font-bold x:tracking-tight">{explainer.title}</h1>
        <div className="x:mt-2 x:text-sm x:text-gray-400">
          {explainer.date} · {explainer.status} · source revision <code>{explainer.sourceCommit.slice(0, 12)}</code>
        </div>
        <p className="x:mt-2 x:text-sm x:text-gray-400">{explainer.summary}</p>
        <div className="x:mt-8 x:text-gray-800 x:dark:text-gray-200">
          {bodyParagraphs.map((paragraph, index) =>
            paragraph.startsWith('## ') ? (
              <h2 key={index} className={headingClass}>{renderInlineMarkdown(paragraph.slice(3))}</h2>
            ) : paragraph.startsWith('### ') ? (
              <h3 key={index} className="x:mt-6 x:text-lg x:font-semibold">{renderInlineMarkdown(paragraph.slice(4))}</h3>
            ) : (
              <p key={index} className="x:not-first:mt-[1.25em] x:leading-7 x:whitespace-pre-wrap">
                {renderInlineMarkdown(paragraph)}
              </p>
            ),
          )}
        </div>
      </article>
      {explainer.claimRefs.length > 0 && (
        <div className="x:mt-8 x:border-t x:pt-4 x:text-sm x:text-gray-400">
          Claim references checked against{' '}
          <code>{explainer.sourceCommit.slice(0, 12)}</code>:{' '}
          {explainer.claimRefs.map((ref, index) => (
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
