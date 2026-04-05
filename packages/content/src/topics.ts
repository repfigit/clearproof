import { readContentFile, listContentSlugs } from './parser.js';

export interface TopicMeta {
  slug: string;
  title: string;
  category: string;
  order: number;
}

export interface Topic extends TopicMeta {
  body: string;
}

/**
 * List all available topics with metadata (no body).
 */
export function listTopics(): TopicMeta[] {
  const slugs = listContentSlugs('topics');
  const topics: TopicMeta[] = [];

  for (const slug of slugs) {
    const { frontmatter } = readContentFile(`topics/${slug}.md`);
    topics.push({
      slug,
      title: (frontmatter['title'] as string) ?? slug,
      category: (frontmatter['category'] as string) ?? 'general',
      order: (frontmatter['order'] as number) ?? 999,
    });
  }

  return topics.sort((a, b) => a.order - b.order);
}

/**
 * Get a single topic by slug, including the markdown body.
 */
export function getTopic(slug: string): Topic | null {
  try {
    const { frontmatter, body } = readContentFile(`topics/${slug}.md`);
    return {
      slug,
      title: (frontmatter['title'] as string) ?? slug,
      category: (frontmatter['category'] as string) ?? 'general',
      order: (frontmatter['order'] as number) ?? 999,
      body,
    };
  } catch {
    return null;
  }
}
