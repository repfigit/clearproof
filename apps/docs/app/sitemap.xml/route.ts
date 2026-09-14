import { getUpdate, listUpdates } from "@clearproof/content";
import { buildSitemapXml } from "../../src/feed";

// Pause switch inside buildSitemapXml must be evaluated per request, not
// frozen at build time by route prerendering.
export const dynamic = "force-dynamic";

export async function GET() {
  const updates = listUpdates()
    .map(update => getUpdate(update.slug))
    .filter(update => update !== null);

  return new Response(buildSitemapXml(updates), {
    status: 200,
    headers: {
      "Cache-Control": "public, max-age=300",
      "Content-Type": "application/xml; charset=utf-8",
    },
  });
}
