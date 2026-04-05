import { NextResponse } from "next/server";
import { getRecipe } from "@clearproof/content";

const headers = { "Cache-Control": "public, max-age=300" };

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params;
  const recipe = getRecipe(slug);

  if (!recipe) {
    return NextResponse.json({ error: "Not found" }, { status: 404, headers });
  }

  return NextResponse.json(recipe, { headers });
}
