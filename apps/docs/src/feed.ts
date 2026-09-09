import { getUpdate, listUpdates, type Update } from "@clearproof/content";

const SITE_URL = (process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.clearproof.world").replace(/\/$/, "");
const FEED_PATH = "/feed.xml";
const FEED_LIMIT = Number.parseInt(process.env.FEED_LIMIT ?? "20", 10);

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function paragraphText(markdown: string): string {
  const withoutMarkup = markdown
    // fenced code blocks
    .replace(/```[\s\S]*?```/g, " ")
    // images
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    // headings, blockquotes, list markers, emphasis
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^>\s?/gm, "")
    .replace(/^\s*[-*+]\s+/gm, "")
    .replace(/[*_`]/g, "")
    // links become their text
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1");
  return withoutMarkup.replace(/\s+/g, " ").trim();
}

function toRfc822(isoDate: string): string {
  const parsed = new Date(isoDate);
  if (Number.isNaN(parsed.getTime())) return "";
  return parsed.toUTCString();
}

export function visibleUpdates(updates: Update[], now: Date = new Date()): Update[] {
  return updates
    .filter(update => update.status === "published" || update.status === "approved")
    .filter(update => Date.parse(update.publishAfter) <= now.getTime());
}

export function buildFeedXml(updates: Update[], generatedAt: Date = new Date()): string {
  const items = visibleUpdates(updates, generatedAt).slice(0, FEED_LIMIT);

  const itemXml = items
    .map(update => {
      const url = `${SITE_URL}/updates/${update.slug}`;
      const description = paragraphText(update.body).slice(0, 300);
      return [
        "    <item>",
        `      <title>${escapeXml(update.title)}</title>`,
        `      <link>${url}</link>`,
        `      <guid isPermaLink="true">${url}</guid>`,
        `      <pubDate>${toRfc822(update.date) || escapeXml(update.date)}</pubDate>`,
        `      <description>${escapeXml(description)}</description>`,
        "    </item>",
      ].join("\n");
    })
    .join("\n");

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    "  <channel>",
    `    <title>Clearproof updates</title>`,
    `    <link>${SITE_URL}</link>`,
    `    <description>Source-backed project updates from Clearproof, pilot-stage zero-knowledge transfer evidence.</description>`,
    `    <language>en</language>`,
    `    <lastBuildDate>${generatedAt.toUTCString()}</lastBuildDate>`,
    `    <atom:link href="${SITE_URL}${FEED_PATH}" rel="self" type="application/rss+xml"/>`,
    itemXml ? `\n${itemXml}\n  ` : "",
    "  </channel>",
    "</rss>",
    "",
  ].join("\n");
}

export function buildSitemapXml(updates: Update[], generatedAt: Date = new Date()): string {
  const entries = [
    { loc: `${SITE_URL}/`, lastmod: undefined as string | undefined },
    { loc: `${SITE_URL}/updates`, lastmod: visibleUpdates(updates, generatedAt)[0]?.date },
    ...visibleUpdates(updates, generatedAt).map(update => ({
      loc: `${SITE_URL}/updates/${update.slug}`,
      lastmod: update.date,
    })),
  ];

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...entries.map(
      entry =>
        `  <url><loc>${escapeXml(entry.loc)}</loc>${
          entry.lastmod ? `<lastmod>${escapeXml(entry.lastmod)}</lastmod>` : ""
        }</url>`,
    ),
    "</urlset>",
    "",
  ].join("\n");
}
