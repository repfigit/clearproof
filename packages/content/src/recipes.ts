import { readContentFile, listContentSlugs } from './parser.js';

export interface RecipeMeta {
  slug: string;
  title: string;
  prereqs: string[];
  estimatedTime: string;
}

export interface Recipe extends RecipeMeta {
  body: string;
  steps: RecipeStep[];
}

export interface RecipeStep {
  description: string;
  command: string;
  expected: string;
}

/**
 * Parse ```bash:run fenced code blocks and the "Expected:" line that follows each one.
 * Returns structured steps with description, command, and expected output.
 */
function parseSteps(body: string): RecipeStep[] {
  const steps: RecipeStep[] = [];
  const lines = body.split('\n');

  let i = 0;
  while (i < lines.length) {
    // Look for ```bash:run
    if (lines[i].trim() === '```bash:run') {
      // Walk backwards to find the description (last non-empty line before the fence)
      let description = '';
      for (let j = i - 1; j >= 0; j--) {
        const trimmed = lines[j].trim();
        if (trimmed !== '') {
          // Strip markdown heading prefix
          description = trimmed.replace(/^#+\s*/, '');
          break;
        }
      }

      // Collect the command (everything between the fences)
      i++;
      const commandLines: string[] = [];
      while (i < lines.length && lines[i].trim() !== '```') {
        commandLines.push(lines[i]);
        i++;
      }
      // Skip closing fence
      if (i < lines.length) i++;

      const command = commandLines.join('\n').trim();

      // Look for "Expected:" line after the code block
      let expected = '';
      while (i < lines.length) {
        const trimmed = lines[i].trim();
        if (trimmed === '') {
          i++;
          continue;
        }
        if (trimmed.toLowerCase().startsWith('expected:')) {
          expected = trimmed.replace(/^expected:\s*/i, '').trim();
          i++;
        }
        break;
      }

      steps.push({ description, command, expected });
      continue;
    }

    i++;
  }

  return steps;
}

/**
 * List all available recipes with metadata (no body or steps).
 */
export function listRecipes(): RecipeMeta[] {
  const slugs = listContentSlugs('recipes');
  const recipes: RecipeMeta[] = [];

  for (const slug of slugs) {
    const { frontmatter } = readContentFile(`recipes/${slug}.md`);
    recipes.push({
      slug,
      title: (frontmatter['title'] as string) ?? slug,
      prereqs: (frontmatter['prereqs'] as string[]) ?? [],
      estimatedTime: (frontmatter['estimated-time'] as string) ?? 'unknown',
    });
  }

  return recipes;
}

/**
 * Get a single recipe by slug, including body and parsed steps.
 */
export function getRecipe(slug: string): Recipe | null {
  try {
    const { frontmatter, body } = readContentFile(`recipes/${slug}.md`);
    return {
      slug,
      title: (frontmatter['title'] as string) ?? slug,
      prereqs: (frontmatter['prereqs'] as string[]) ?? [],
      estimatedTime: (frontmatter['estimated-time'] as string) ?? 'unknown',
      body,
      steps: parseSteps(body),
    };
  } catch {
    return null;
  }
}

/**
 * Get just the executable steps for a recipe.
 */
export function getRecipeSteps(slug: string): RecipeStep[] {
  const recipe = getRecipe(slug);
  return recipe?.steps ?? [];
}
