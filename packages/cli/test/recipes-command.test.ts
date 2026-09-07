import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { stripVTControlCharacters } from 'node:util';

const mocks = vi.hoisted(() => ({
  list: vi.fn(), get: vi.fn(), execute: vi.fn(), question: vi.fn(), close: vi.fn(),
}));
vi.mock('@clearproof/content', () => ({ listRecipes: mocks.list, getRecipe: mocks.get }));
vi.mock('child_process', () => ({ execFile: mocks.execute }));
vi.mock('readline', () => ({ createInterface: () => ({ question: mocks.question, close: mocks.close }) }));
const step = { description: 'Print synthetic text', command: 'echo "hello world"', expected: 'hello world' };
const recipe = { slug: 'sample', title: 'Sample recipe', prereqs: ['node'], estimatedTime: '1m',
  body: '# Sample recipe\nRead the instructions.', steps: [step] };
let output: ReturnType<typeof vi.spyOn>;
let errors: ReturnType<typeof vi.spyOn>;
let exit: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  vi.resetModules();
  for (const fn of Object.values(mocks)) fn.mockReset();
  mocks.list.mockReturnValue([recipe]);
  mocks.get.mockReturnValue(recipe);
  mocks.question.mockImplementation((_prompt, callback) => callback(''));
  mocks.execute.mockImplementation((_program, _args, _options, callback) => callback(null, 'hello world', ''));
  output = vi.spyOn(console, 'log').mockImplementation(() => {});
  errors = vi.spyOn(console, 'error').mockImplementation(() => {});
  exit = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('synthetic exit'); });
});
afterEach(() => vi.restoreAllMocks());
async function run(args: string[]) {
  const { recipesCommand } = await import('../src/commands/recipes.js');
  await recipesCommand.parseAsync(args, { from: 'user' });
}
const printed = () => stripVTControlCharacters(output.mock.calls.flat().join('\n'));
const rejected = () => stripVTControlCharacters(errors.mock.calls.flat().join('\n'));

describe('recipe browsing and interactive execution', () => {
  it('lists recipes and renders instructions without executing them', async () => {
    await run([]);
    expect(printed()).toContain('Available recipes:');
    expect(printed()).toContain('Sample recipe');
    expect(printed()).toContain('(1m)');
    output.mockClear();
    await run(['sample']);
    expect(printed()).toContain('Read the instructions.');
    expect(mocks.question).not.toHaveBeenCalled();
    expect(mocks.execute).not.toHaveBeenCalled();
  });
  it('rejects missing recipes with a failing exit status', async () => {
    mocks.get.mockReturnValue(null);
    await expect(run(['missing'])).rejects.toThrow('synthetic exit');
    expect(rejected()).toContain('Unknown recipe: missing');
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
  it('requires interactive consent and passes quoted arguments without a shell', async () => {
    await run(['sample', '--run']);
    expect(mocks.question).toHaveBeenCalledOnce();
    expect(mocks.close).toHaveBeenCalledOnce();
    expect(mocks.execute).toHaveBeenCalledExactlyOnceWith('echo', ['hello world'], { timeout: 60000 }, expect.any(Function));
    expect(printed()).toContain('Prereqs: node');
    expect(printed()).toContain('Expected: hello world');
    expect(printed()).toContain('Recipe complete.');
    expect(errors).not.toHaveBeenCalled();
  });
  it('honors a trimmed, case-insensitive skip answer', async () => {
    mocks.question.mockImplementation((_prompt, callback) => callback(' N '));
    await run(['sample', '--run']);
    expect(mocks.execute).not.toHaveBeenCalled();
    expect(printed()).toContain('Skipped.');
    expect(mocks.close).toHaveBeenCalledOnce();
  });
  it('stops after a failed command when continuation is declined', async () => {
    mocks.execute.mockImplementation((_program, _args, _options, callback) => callback({ code: 'ENOENT' }, '', 'not found'));
    await expect(run(['sample', '--run'])).rejects.toThrow('synthetic exit');
    expect(rejected()).toContain('not found');
    expect(rejected()).toContain('Step failed with exit code 1');
    expect(mocks.close).toHaveBeenCalledTimes(2);
    expect(printed()).not.toContain('Recipe complete.');
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
  it('continues only after explicit consent following a failure', async () => {
    mocks.get.mockReturnValue({ ...recipe, prereqs: [], steps: [{ ...step, expected: '' }, step] });
    mocks.question.mockImplementationOnce((_prompt, cb) => cb(''))
      .mockImplementationOnce((_prompt, cb) => cb(' Y '));
    mocks.execute.mockImplementationOnce((_program, _args, _options, callback) => callback(new Error('failed'), undefined, undefined));
    await run(['sample', '--run']);
    expect(mocks.execute).toHaveBeenCalledTimes(2);
    expect(mocks.close).toHaveBeenCalledTimes(3);
    expect(printed()).not.toContain('Prereqs:');
    expect(printed()).toContain('Recipe complete.');
    expect(exit).not.toHaveBeenCalled();
  });
  it('propagates invalid executable errors instead of claiming a step succeeded', async () => {
    mocks.get.mockReturnValue({ ...recipe, steps: [{ ...step, command: '' }] });
    mocks.execute.mockImplementation(() => { throw new TypeError('file must be a string'); });
    await expect(run(['sample', '--run'])).rejects.toThrow('file must be a string');
    expect(printed()).not.toContain('Recipe complete.');
  });
});
