import Link from 'next/link';
import { getUpdate, listUpdates } from '@clearproof/content';
import { visibleUpdates } from '../../src/feed';

export const metadata = {
  title: 'Updates — clearproof',
  description: 'Source-backed project updates from Clearproof, pilot-stage zero-knowledge transfer evidence.',
};

export default function UpdatesIndex() {
  const updates = visibleUpdates(
    listUpdates().map(update => getUpdate(update.slug)).filter(update => update !== null),
  );
  return (
    <main className="x:mx-auto x:w-full x:max-w-(--nextra-content-width) x:px-4 x:py-12">
      <h1 className="x:text-3xl x:font-bold x:tracking-tight">Updates</h1>
      <p className="x:mt-2 x:text-sm x:text-gray-400">
        Source-backed project updates. Subscribe via{' '}
        <a className="x:underline" href="/feed.xml">RSS (/feed.xml)</a>. Each update cites the
        source revision its claims were checked against. Clearproof is pilot-stage software;
        updates describe the repository as it is, without audit, customer or compliance claims.
      </p>
      <ul className="x:mt-8 x:flex x:flex-col x:gap-4">
        {updates.map(update => (
          <li key={update.id}>
            <Link className="x:text-xl x:font-semibold x:underline" href={`/updates/${update.slug}`}>
              {update.title}
            </Link>
            <div className="x:mt-1 x:text-sm x:text-gray-400">
              {update.date} · {update.status}
            </div>
            <p className="x:mt-2 x:text-gray-700 x:dark:text-gray-300">{update.summary}</p>
          </li>
        ))}
      </ul>
      {updates.length === 0 && (
        <p className="x:mt-8 x:text-gray-400">No updates published yet.</p>
      )}
    </main>
  );
}
