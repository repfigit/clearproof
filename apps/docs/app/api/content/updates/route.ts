import { NextResponse } from "next/server";
import { listUpdates } from "@clearproof/content";

const headers = { "Cache-Control": "public, max-age=300" };

export async function GET() {
  return NextResponse.json({ updates: listUpdates() }, { headers });
}
