import { getUpdate, listUpdates } from "@clearproof/content";
import { buildFeedXml } from "../../src/feed";

export async function GET() {
  const updates = listUpdates()
    .map(update => getUpdate(update.slug))
    .filter(update => update !== null);

  return new Response(buildFeedXml(updates), {
    status: 200,
    headers: {
      "Cache-Control": "public, max-age=300",
      "Content-Type": "application/rss+xml; charset=utf-8",
    },
  });
}
