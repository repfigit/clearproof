import chalk from 'chalk';

/**
 * Basic markdown-to-terminal renderer.
 *
 * Handles the subset of Markdown used in @clearproof/content help topics
 * and recipes: headers, code blocks, bold, links, and HTML tags.
 */
export function renderMarkdown(md: string): string {
  const lines = md.split('\n');
  const out: string[] = [];
  let inCodeBlock = false;

  for (const line of lines) {
    // --- Code block fences ---
    if (line.trimStart().startsWith('```')) {
      inCodeBlock = !inCodeBlock;
      if (inCodeBlock) {
        // Opening fence — emit a blank line for spacing
        out.push('');
      }
      continue;
    }

    if (inCodeBlock) {
      out.push('    ' + chalk.dim(line));
      continue;
    }

    // --- Headers ---
    if (line.startsWith('# ')) {
      out.push('');
      out.push(chalk.bold.cyan(line.slice(2)));
      out.push('');
      continue;
    }
    if (line.startsWith('## ')) {
      out.push('');
      out.push(chalk.bold.white(line.slice(3)));
      out.push('');
      continue;
    }
    if (line.startsWith('### ')) {
      out.push('');
      out.push(chalk.bold(line.slice(4)));
      out.push('');
      continue;
    }

    // --- Inline formatting ---
    let rendered = line;

    // Bold: **text** -> chalk.bold(text)
    rendered = rendered.replace(/\*\*(.+?)\*\*/g, (_m, p1: string) =>
      chalk.bold(p1),
    );

    // Links: [text](url) -> text (url)
    rendered = rendered.replace(
      /\[(.+?)\]\((.+?)\)/g,
      (_m, text: string, url: string) => `${text} ${chalk.dim('(' + url + ')')}`,
    );

    // Strip HTML tags
    rendered = rendered.replace(/<[^>]+>/g, '');

    out.push(rendered);
  }

  return out.join('\n');
}
