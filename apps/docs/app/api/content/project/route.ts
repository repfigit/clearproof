import { NextResponse } from 'next/server';
import { getExplainer, listExplainers, PROJECT_STATUS } from '@clearproof/content';
import { gatedVisible, visibleExplainers } from '../../../../src/feed';

// Publication dates and the pause switch are evaluated on every request.
export const dynamic = 'force-dynamic';

export async function GET() {
  const explainers = gatedVisible(visibleExplainers(
    listExplainers().map(item => getExplainer(item.slug)).filter(item => item !== null),
  )).map(({ slug, title, publishAfter }) => ({ slug, title, publishAfter }));
  return NextResponse.json({ ...PROJECT_STATUS, explainers }, {
    headers: { 'Cache-Control': 'public, max-age=300' },
  });
}
