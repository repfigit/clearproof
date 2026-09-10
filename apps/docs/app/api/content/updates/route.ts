import { NextResponse } from "next/server";
import { getUpdate, listUpdates } from "@clearproof/content";
import { visibleUpdates } from "../../../../src/feed";

const headers = { "Cache-Control": "public, max-age=300" };

export async function GET() {
  const updates = listUpdates()
    .map(update => getUpdate(update.slug))
    .filter(update => update !== null);

  return NextResponse.json({ updates: visibleUpdates(updates) }, { headers });
}
