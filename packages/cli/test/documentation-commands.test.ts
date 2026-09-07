import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { stripVTControlCharacters } from 'node:util';
import { renderMarkdown } from '../src/render.js';

let output: ReturnType<typeof vi.spyOn>;
let errors: ReturnType<typeof vi.spyOn>;
let exit: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  vi.resetModules();
  output = vi.spyOn(console, 'log').mockImplementation(() => {});
  errors = vi.spyOn(console, 'error').mockImplementation(() => {});
  exit = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('synthetic process exit'); });
});
afterEach(() => vi.restoreAllMocks());
const printed = () => stripVTControlCharacters(output.mock.calls.flat().join('\n'));
const rejected = () => stripVTControlCharacters(errors.mock.calls.flat().join('\n'));

describe('terminal markdown rendering', () => {
  it('renders headings, inline formatting and literal code contents', () => {
    const result = stripVTControlCharacters(renderMarkdown(
      '# Title\n## Section\n### Detail\n**Bold** [Docs](https://docs.example) <b>text</b>\n' +
      '  ```bash\n# literal heading\n**literal emphasis**\n```\nplain',
    ));
    expect(result).toContain('\nTitle\n\n\nSection\n\n\nDetail\n');
    expect(result).toContain('Bold Docs (https://docs.example) text');
    expect(result).toContain('    # literal heading\n    **literal emphasis**');
    expect(result).toMatch(/\nplain$/);
    expect(result).not.toContain('```');
    expect(renderMarkdown('')).toBe('');
  });
});

describe('packaged documentation commands', () => {
  it('lists available help topics and renders an actual topic', async () => {
    const { helpCommand } = await import('../src/commands/help.js');
    await helpCommand.parseAsync([], { from: 'user' });
    expect(printed()).toContain('Available topics:');
    expect(printed()).toContain('clearproof help <topic>');
    expect(printed()).toContain('api');
    output.mockClear();
    await helpCommand.parseAsync(['api'], { from: 'user' });
    expect(printed()).toContain('/wallet/ownership/verify');
    expect(errors).not.toHaveBeenCalled();
    expect(exit).not.toHaveBeenCalled();
  });
  it('reports an unknown topic with a failing exit status', async () => {
    const { helpCommand } = await import('../src/commands/help.js');
    await expect(helpCommand.parseAsync(['nonexistent-synthetic-topic'], { from: 'user' }))
      .rejects.toThrow('synthetic process exit');
    expect(rejected()).toContain('Unknown topic: nonexistent-synthetic-topic');
    expect(rejected()).toContain('clearproof help');
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
  it.each([
    ['is_compliant', 'yes (public output)'],
    ['credential_nullifier', 'no (public input)'],
  ])('explains %s using the packaged signal definition', async (name, expectedOutput) => {
    const { explainCommand } = await import('../src/commands/explain.js');
    await explainCommand.parseAsync([name], { from: 'user' });
    expect(printed()).toContain(name);
    expect(printed()).toContain(expectedOutput);
    expect(printed()).toContain('Source:');
    expect(printed()).toContain('On-chain:');
    expect(errors).not.toHaveBeenCalled();
  });
  it('lists alternatives and exits unsuccessfully for unknown signals', async () => {
    const { explainCommand } = await import('../src/commands/explain.js');
    await expect(explainCommand.parseAsync(['unknown-synthetic-signal'], { from: 'user' }))
      .rejects.toThrow('synthetic process exit');
    expect(rejected()).toContain('Unknown signal: unknown-synthetic-signal');
    expect(rejected()).toContain('Available signals:');
    expect(rejected()).toContain('credential_nullifier');
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
});
