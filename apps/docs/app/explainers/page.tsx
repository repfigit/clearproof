import Link from 'next/link';
import { getExplainer, listExplainers } from '@clearproof/content';
import { visibleExplainers } from '../../src/feed';

export const metadata = {
  title: 'Explainers — clearproof',
  description: 'Canonical source-backed explainers from Clearproof, pilot-stage zero-knowledge transfer evidence.',
};

export default function ExplainersIndex() {
  const explainers = visibleExplainers(
    listExplainers().map(explainer => getExplainer(explainer.slug)).filter(explainer => explainer !== null),
  );
  return (
    <main className="x:mx-auto x:w-full x:max-w-(--nextra-content-width) x:px-4 x:py-12">
      <h1 className="x:text-3xl x:font-bold x:tracking-tight">Explainers</h1>
      <p className="x:mt-2 x:text-sm x:text-gray-400">
        Canonical source-backed explainers. Each explainer cites the source revision
        its claims were checked against. Clearproof is pilot-stage software; these
        pages describe the repository as it is, without audit, customer or
        compliance claims. For shorter, change-driven items see{' '}
        <Link className="x:underline" href="/updates">Updates</Link> and the{' '}
        <a className="x:underline" href="/feed.xml">RSS feed</a>.
      </p>
      <ul className="x:mt-8 x:flex x:flex-col x:gap-4">
        {explainers.map(explainer => (
          <li key={explainer.id}>
            <Link className="x:text-xl x:font-semibold x:underline" href={explainer.canonical}>
              {explainer.title}
            </Link>
            <div className="x:mt-1 x:text-sm x:text-gray-400">
              {explainer.date} · {explainer.status}
            </div>
            <p className="x:mt-2 x:text-gray-700 x:dark:text-gray-300">{explainer.summary}</p>
          </li>
        ))}
      </ul>
      {explainers.length === 0 && (
        <p className="x:mt-8 x:text-gray-400">No explainers published yet.</p>
      )}
    </main>
  );
}
