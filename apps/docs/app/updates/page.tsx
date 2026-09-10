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
    <main className="mx-auto w-full max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-bold tracking-tight">Updates</h1>
      <p className="mt-2 text-sm text-gray-500">
        Source-backed project updates. Subscribe via{' '}
        <a className="underline" href="/feed.xml">RSS (/feed.xml)</a>. Each update cites the
        source revision its claims were checked against. Clearproof is pilot-stage software;
        updates describe the repository as it is, without audit, customer or compliance claims.
      </p>
      <ul className="mt-8 space-y-8">
        {updates.map(update => (
          <li key={update.id}>
            <Link className="text-xl font-semibold underline-offset-4 hover:underline" href={`/updates/${update.slug}`}>
              {update.title}
            </Link>
            <div className="mt-1 text-sm text-gray-500">
              {update.date} · {update.status}
            </div>
            <p className="mt-2 text-gray-700 dark:text-gray-300">{update.summary}</p>
          </li>
        ))}
      </ul>
      {updates.length === 0 && (
        <p className="mt-8 text-gray-500">No updates published yet.</p>
      )}
    </main>
  );
}
