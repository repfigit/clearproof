import { NextResponse } from "next/server";
import { getUpdate, listUpdates } from "@clearproof/content";
import { gatedVisible, visibleUpdates } from "../../../../src/feed";
import { pauseNotice, publishingEnabled } from "../../../../src/publish-controls";

const headers = { "Cache-Control": "public, max-age=300" };

export async function GET() {
  if (!publishingEnabled()) {
    return NextResponse.json({ paused: true, message: pauseNotice() }, { headers });
  }
  const updates = listUpdates()
    .map(update => getUpdate(update.slug))
    .filter(update => update !== null);

  return NextResponse.json({ updates: gatedVisible(visibleUpdates(updates)) }, { headers });
}
