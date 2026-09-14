import { readContentFile, listContentSlugs } from './parser.js';

export interface ExplainerMeta {
  id: string;
  slug: string;
  title: string;
  date: string;
  /** UTC timestamp after which the explainer may be published. */
  publishAfter: string;
  /** Source revision the claims were validated against. */
  sourceCommit: string;
  claimRefs: string[];
  status: 'draft' | 'validated' | 'approved' | 'published';
  summary: string;
  /** Canonical site path for this explainer, e.g. /explainers/what-clearproof-does. */
  canonical: string;
  /** Editorial template version; approval is bound to template + body. */
  templateVersion: string;
}

export interface Explainer extends ExplainerMeta {
  body: string;
}

const EXPLAINER_FIELDS = [
  'id',
  'title',
  'date',
  'publishAfter',
  'sourceCommit',
  'status',
  'summary',
  'canonical',
  'templateVersion',
] as const;

function requiredStringFields(frontmatter: Record<string, unknown>): string[] {
  return EXPLAINER_FIELDS.filter((field) => typeof frontmatter[field] !== 'string' || frontmatter[field] === '');
}

function normalizeStatus(value: string): ExplainerMeta['status'] {
  return (['draft', 'validated', 'approved', 'published'] as const).includes(value as never)
    ? (value as ExplainerMeta['status'])
    : 'draft';
}

function toMeta(slug: string, frontmatter: Record<string, unknown>): ExplainerMeta | null {
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
    canonical: frontmatter['canonical'] as string,
    templateVersion: frontmatter['templateVersion'] as string,
  };
}

/**
 * List all explainers with metadata (no body), sorted newest first by ISO date.
 */
export function listExplainers(): ExplainerMeta[] {
  const slugs = listContentSlugs('explainers');
  const explainers: ExplainerMeta[] = [];
  for (const slug of slugs) {
    const { frontmatter } = readContentFile(`explainers/${slug}.md`);
    const meta = toMeta(slug, frontmatter);
    if (meta) explainers.push(meta);
  }
  return explainers.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.slug.localeCompare(b.slug)));
}

/**
 * Get a single explainer by slug, including the markdown body.
 */
export function getExplainer(slug: string): Explainer | null {
  try {
    const { frontmatter, body } = readContentFile(`explainers/${slug}.md`);
    const meta = toMeta(slug, frontmatter);
    return meta ? { ...meta, body } : null;
  } catch {
    return null;
  }
}
