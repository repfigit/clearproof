import { NextResponse } from "next/server";
import { listTopics, listRecipes, listSignals } from "@clearproof/content";

const headers = { "Cache-Control": "public, max-age=300" };

export async function GET() {
  const manifest = {
    topics: listTopics(),
    recipes: listRecipes(),
    signals: listSignals(),
  };

  return NextResponse.json(manifest, { headers });
}
