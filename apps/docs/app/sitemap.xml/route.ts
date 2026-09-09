import { getUpdate, listUpdates } from "@clearproof/content";
import { buildSitemapXml } from "../../src/feed";

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
