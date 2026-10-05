import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Markdown } from '../../components/markdown';
import { getExplainer, listExplainers } from '@clearproof/content';
import { gatedVisible, visibleExplainers } from '../../../src/feed';

// Pause switch must be evaluated per request, not frozen at build time.
export const dynamic = 'force-dynamic';

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

export default async function ExplainerPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const explainers = gatedVisible(
    visibleExplainers(listExplainers().map(item => getExplainer(item.slug)).filter(item => item !== null)),
  );
  const explainer = explainers.find(item => item.slug === slug);
  if (!explainer) notFound();

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
          <Markdown>{explainer.body}</Markdown>
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
