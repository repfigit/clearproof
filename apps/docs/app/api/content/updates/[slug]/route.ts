import { NextResponse } from "next/server";
import { getUpdate } from "@clearproof/content";

const headers = { "Cache-Control": "public, max-age=300" };

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params;
  const update = getUpdate(slug);

  if (!update) {
    return NextResponse.json({ error: "Not found" }, { status: 404, headers });
  }

  return NextResponse.json(update, { headers });
}
