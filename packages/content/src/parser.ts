import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { readdirSync } from 'node:fs';

/** Base directory for all content files, resolved relative to this file's compiled location. */
const CONTENT_DIR = resolve(__dirname, '..', 'content');

export interface Frontmatter {
  [key: string]: unknown;
}

export interface ParsedFile {
  frontmatter: Frontmatter;
  body: string;
}

/**
 * Parse a markdown file with YAML frontmatter delimited by `---`.
 * Uses a simple regex split -- no external frontmatter library needed.
 */
export function parseFrontmatter(raw: string): ParsedFile {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) {
    return { frontmatter: {}, body: raw };
  }

  const yamlBlock = match[1];
  const body = match[2].trim();

  // Simple YAML key-value parser (handles strings, numbers, arrays)
  const frontmatter: Frontmatter = {};
  let currentKey: string | null = null;
  let currentArray: string[] | null = null;

  for (const line of yamlBlock.split('\n')) {
    const trimmed = line.trim();

    // Array item continuation
    if (trimmed.startsWith('- ') && currentKey && currentArray !== null) {
      currentArray.push(trimmed.slice(2).trim());
      continue;
    }

    // Flush any pending array
    if (currentKey && currentArray !== null) {
      frontmatter[currentKey] = currentArray;
      currentArray = null;
      currentKey = null;
    }

    // Key-value pair
    const kvMatch = trimmed.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
    if (!kvMatch) continue;

    const key = kvMatch[1];
    const value = kvMatch[2].trim();

    if (value === '') {
      // Start of an array or empty value -- look ahead
      currentKey = key;
      currentArray = [];
      continue;
    }

    // Parse value types
    if (value === 'true') {
      frontmatter[key] = true;
    } else if (value === 'false') {
      frontmatter[key] = false;
    } else if (/^\d+$/.test(value)) {
      frontmatter[key] = parseInt(value, 10);
    } else {
      frontmatter[key] = value;
    }
  }

  // Flush trailing array
  if (currentKey && currentArray !== null) {
    frontmatter[currentKey] = currentArray;
  }

  return { frontmatter, body };
}

/**
 * Read and parse a markdown file from the content directory.
 */
export function readContentFile(relativePath: string): ParsedFile {
  const fullPath = join(CONTENT_DIR, relativePath);
  const raw = readFileSync(fullPath, 'utf-8');
  return parseFrontmatter(raw);
}

/**
 * List all .md files in a subdirectory of the content directory.
 * Returns filenames without extension (slugs).
 */
export function listContentSlugs(subdir: string): string[] {
  const dir = join(CONTENT_DIR, subdir);
  try {
    return readdirSync(dir)
      .filter((f) => f.endsWith('.md'))
      .map((f) => f.replace(/\.md$/, ''))
      .sort();
  } catch {
    return [];
  }
}

export { CONTENT_DIR };
