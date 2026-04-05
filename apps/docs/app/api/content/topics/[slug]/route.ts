import { NextResponse } from "next/server";
import { getTopic } from "@clearproof/content";

const headers = { "Cache-Control": "public, max-age=300" };

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params;
  const topic = getTopic(slug);

  if (!topic) {
    return NextResponse.json({ error: "Not found" }, { status: 404, headers });
  }

  return NextResponse.json(topic, { headers });
}
