import { readContentFile, listContentSlugs, CONTENT_DIR } from './parser.js';

export interface UpdateMeta {
  id: string;
  slug: string;
  title: string;
  date: string;
  /** UTC timestamp after which the update may be published. */
  publishAfter: string;
  /** Source revision the claims were validated against. */
  sourceCommit: string;
  claimRefs: string[];
  status: 'draft' | 'validated' | 'approved' | 'published';
  summary: string;
}

export interface Update extends UpdateMeta {
  body: string;
}

const UPDATE_FIELDS = [
  'id',
  'title',
  'date',
  'publishAfter',
  'sourceCommit',
  'status',
  'summary',
] as const;

function requiredStringFields(frontmatter: Record<string, unknown>): string[] {
  return UPDATE_FIELDS.filter((field) => typeof frontmatter[field] !== 'string' || frontmatter[field] === '');
}

function normalizeStatus(value: string): UpdateMeta['status'] {
  return (['draft', 'validated', 'approved', 'published'] as const).includes(value as never)
    ? (value as UpdateMeta['status'])
    : 'draft';
}

function toMeta(slug: string, frontmatter: Record<string, unknown>): UpdateMeta | null {
  const missing = requiredStringFields(frontmatter);
  if (missing.length > 0) return null;
  const claimRefs = frontmatter['claimRefs'];
  return {
    id: frontmatter['id'] as string,
    slug,
    title: frontmatter['title'] as string,
    date: frontmatter['date'] as string,
    publishAfter: frontmatter['publishAfter'] as string,
    sourceCommit: frontmatter['sourceCommit'] as string,
    claimRefs: Array.isArray(claimRefs) ? claimRefs.filter((ref): ref is string => typeof ref === 'string') : [],
    status: normalizeStatus(frontmatter['status'] as string),
    summary: frontmatter['summary'] as string,
  };
}

/**
 * List all updates with metadata (no body), sorted newest first by ISO date.
 */
export function listUpdates(): UpdateMeta[] {
  const slugs = listContentSlugs('updates');
  const updates: UpdateMeta[] = [];
  for (const slug of slugs) {
    const { frontmatter } = readContentFile(`updates/${slug}.md`);
    const meta = toMeta(slug, frontmatter);
    if (meta) updates.push(meta);
  }
  return updates.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.slug.localeCompare(b.slug)));
}

/**
 * Get a single update by slug, including the markdown body.
 */
export function getUpdate(slug: string): Update | null {
  try {
    const { frontmatter, body } = readContentFile(`updates/${slug}.md`);
    const meta = toMeta(slug, frontmatter);
    return meta ? { ...meta, body } : null;
  } catch {
    return null;
  }
}

export { CONTENT_DIR };
