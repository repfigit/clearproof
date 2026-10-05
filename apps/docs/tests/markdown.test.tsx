import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it } from 'vitest';
import { Markdown } from '../app/components/markdown';

it('renders document structure, emphasis, code, links and GFM tables', () => {
  const html = renderToStaticMarkup(<Markdown>{[
    '## Evidence', '### Results', '**Bound** and *private* with `field`.',
    '- First\n- Second', '1. Inspect\n2. Compare', '> Quoted explanation',
    '```json\n{"synthetic": true}\n```',
    '| Check | Outcome |\n| --- | --- |\n| Projection | PASS |',
    '[SDK](/docs/sdk) and https://example.com',
  ].join('\n\n')}</Markdown>);
  expect(html).toContain('<h2>Evidence</h2>');
  expect(html).toContain('<h3>Results</h3>');
  expect(html).toContain('<strong>Bound</strong>');
  expect(html).toContain('<em>private</em>');
  expect(html).toContain('<code>field</code>');
  expect(html).toContain('<ul>');
  expect(html).toContain('<ol>');
  expect(html).toContain('<blockquote>');
  expect(html).toContain('<pre><code class="language-json">');
  expect(html).toContain('<table>');
  expect(html).toContain('<td>PASS</td>');
  expect(html).toContain('href="/docs/sdk"');
  expect(html).toContain('href="https://example.com"');
  expect(html).not.toContain('**Bound**');
});

it('disables embedded HTML and unsafe Markdown URL schemes', () => {
  const html = renderToStaticMarkup(<Markdown>{
    '<script>alert(1)</script>\n\n<img src="x" onerror="alert(1)">\n\n[unsafe](javascript:alert%281%29)'
  }</Markdown>);
  expect(html).not.toContain('<script');
  expect(html).not.toContain('<img');
  expect(html).not.toContain('javascript:');
  expect(html).not.toContain('onerror');
  expect(html).toContain('unsafe');
});
