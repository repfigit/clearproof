import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { stripVTControlCharacters } from 'node:util';

const mocks = vi.hoisted(() => ({
  list: vi.fn(), get: vi.fn(), execute: vi.fn(), question: vi.fn(), close: vi.fn(),
  opened: vi.fn(), ended: vi.fn(), closeSession: vi.fn(), once: vi.fn(), killSession: vi.fn(),
}));
vi.mock('@clearproof/content', () => ({ listRecipes: mocks.list, getRecipe: mocks.get }));
vi.mock('../src/shell-session.js', () => ({
  ShellSession: class {
    constructor(options: unknown) { mocks.opened(options); }
    get ended() { return mocks.ended(); }
    run(command: string) { return mocks.execute(command); }
    close() { mocks.closeSession(); }
    kill() { mocks.killSession(); }
  },
}));
const ok = { stdout: 'hello world', stderr: '', code: 0, stopped: null, sessionEnded: false };
// Like the real interface, close() emits 'close' synchronously to the registered listener.
vi.mock('readline', () => ({ createInterface: () => {
  let closed = () => {};
  return {
    question: mocks.question,
    once: (event: string, listener: () => void) => { closed = listener; mocks.once(event, listener); },
    close: () => { mocks.close(); closed(); },
  };
} }));
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
  mocks.execute.mockResolvedValue(ok);
  mocks.ended.mockReturnValue(false);
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
  it('never opens a shell or runs a step without --run', async () => {
    await run([]);
    await run(['sample']);
    expect(mocks.opened).not.toHaveBeenCalled();
    expect(mocks.execute).not.toHaveBeenCalled();
  });
  it('requires interactive consent and runs every step in one session with the step limit', async () => {
    mocks.get.mockReturnValue({ ...recipe, steps: [{ ...step, command: 'cd work\nexport NAME=value' }, step] });
    await run(['sample', '--run']);
    expect(mocks.question).toHaveBeenCalledTimes(2);
    expect(mocks.close).toHaveBeenCalledTimes(2);
    expect(mocks.opened).toHaveBeenCalledExactlyOnceWith({ timeoutMs: 60000 });
    expect(mocks.execute.mock.calls).toEqual([['cd work\nexport NAME=value'], ['echo "hello world"']]);
    expect(mocks.closeSession).toHaveBeenCalledOnce();
    expect(printed()).toContain('Steps run in one bash session');
    expect(printed()).toContain('> cd work\n  > export NAME=value');
    expect(printed()).toContain('Prereqs: node');
    expect(printed()).toContain('Expected: hello world');
    expect(printed()).toContain('Recipe complete.');
    expect(errors).not.toHaveBeenCalled();
  });
  it('asks before each step and opens no shell when every step is skipped', async () => {
    mocks.question.mockImplementation((_prompt, callback) => callback(' N '));
    await run(['sample', '--run']);
    expect(mocks.opened).not.toHaveBeenCalled();
    expect(mocks.execute).not.toHaveBeenCalled();
    expect(mocks.closeSession).not.toHaveBeenCalled();
    expect(printed()).toContain('Skipped.');
    expect(mocks.close).toHaveBeenCalledOnce();
  });
  it('stops after a failed command when continuation is declined and closes the session', async () => {
    mocks.execute.mockResolvedValue({ ...ok, stdout: '', stderr: 'not found', code: 127 });
    await expect(run(['sample', '--run'])).rejects.toThrow('synthetic exit');
    expect(rejected()).toContain('not found');
    expect(rejected()).toContain('Step failed with exit code 127');
    expect(mocks.close).toHaveBeenCalledTimes(2);
    expect(mocks.closeSession).toHaveBeenCalledOnce();
    expect(printed()).not.toContain('Recipe complete.');
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
  it('continues only after explicit consent, in a new shell when the first one ended', async () => {
    mocks.get.mockReturnValue({ ...recipe, prereqs: [], steps: [{ ...step, expected: '' }, step, step] });
    mocks.question.mockImplementationOnce((_prompt, cb) => cb(''))
      .mockImplementationOnce((_prompt, cb) => cb(' Y '))
      .mockImplementationOnce((_prompt, cb) => cb(''))
      .mockImplementationOnce((_prompt, cb) => cb('y'));
    mocks.execute.mockResolvedValueOnce({ ...ok, stdout: '', code: 124, stopped: 'timeout', sessionEnded: true })
      .mockResolvedValueOnce({ ...ok, code: 126, stopped: 'output-limit', sessionEnded: true });
    mocks.ended.mockReturnValueOnce(true).mockReturnValueOnce(true).mockReturnValue(false);
    await run(['sample', '--run']);
    expect(mocks.execute).toHaveBeenCalledTimes(3);
    expect(mocks.opened).toHaveBeenCalledTimes(3);
    expect(mocks.closeSession).toHaveBeenCalledTimes(3);
    expect(mocks.close).toHaveBeenCalledTimes(5);
    expect(rejected()).toContain('Step stopped after the 60 second limit');
    expect(rejected()).toContain('Step stopped after exceeding the output limit');
    expect(printed()).toContain('Starting a new shell. Earlier cd and export commands are not carried over.');
    expect(printed()).not.toContain('Prereqs:');
    expect(printed()).toContain('Recipe complete.');
    expect(exit).not.toHaveBeenCalled();
  });
  it('treats closed input as no consent: the step is not run and the command fails', async () => {
    mocks.question.mockImplementation(() => {});
    mocks.once.mockImplementation((event, listener) => { if (event === 'close') listener(); });
    await expect(run(['sample', '--run'])).rejects.toThrow('synthetic exit');
    expect(rejected()).toContain('Input closed before an answer. Stopping; this step was not run.');
    expect(mocks.opened).not.toHaveBeenCalled();
    expect(mocks.execute).not.toHaveBeenCalled();
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
  it('does not prompt or run when input has already ended', async () => {
    Object.defineProperty(process.stdin, 'readableEnded', { configurable: true, get: () => true });
    try {
      await expect(run(['sample', '--run'])).rejects.toThrow('synthetic exit');
    } finally {
      delete (process.stdin as { readableEnded?: boolean }).readableEnded;
    }
    expect(process.stdin.readableEnded).toBe(false);
    expect(mocks.question).not.toHaveBeenCalled();
    expect(mocks.execute).not.toHaveBeenCalled();
    expect(rejected()).toContain('Input closed before an answer.');
  });
  it('stops when input closes at the continue prompt after a failure', async () => {
    mocks.execute.mockResolvedValue({ ...ok, code: 1 });
    mocks.question.mockImplementationOnce((_prompt, cb) => cb('')).mockImplementation(() => {});
    mocks.once.mockImplementationOnce(() => {}).mockImplementation((_event, listener) => listener());
    await expect(run(['sample', '--run'])).rejects.toThrow('synthetic exit');
    expect(mocks.execute).toHaveBeenCalledOnce();
    expect(mocks.closeSession).toHaveBeenCalledOnce();
    expect(printed()).not.toContain('Recipe complete.');
  });
  it('treats a step without a command as a failure instead of claiming it succeeded', async () => {
    mocks.get.mockReturnValue({ ...recipe, steps: [{ ...step, command: ' ' }] });
    await expect(run(['sample', '--run'])).rejects.toThrow('synthetic exit');
    expect(rejected()).toContain('This step has no command.');
    expect(rejected()).toContain('Step failed with exit code 2');
    expect(mocks.opened).not.toHaveBeenCalled();
    expect(printed()).not.toContain('Recipe complete.');
  });
  it('closes the session when a step throws', async () => {
    mocks.execute.mockRejectedValue(new Error('A recipe step is already running'));
    await expect(run(['sample', '--run'])).rejects.toThrow('A recipe step is already running');
    expect(mocks.closeSession).toHaveBeenCalledOnce();
    expect(printed()).not.toContain('Recipe complete.');
  });
  it('says the recipe is not complete when it has manual command blocks that --run skips', async () => {
    const fence = '```';
    mocks.get.mockReturnValue({ ...recipe, body:
      `# Sample\n${fence}bash:run\necho "hello world"\n${fence}\nThen by hand:\n${fence}bash\nmake deploy\n${fence}\n` });
    await run(['sample', '--run']);
    expect(printed()).toContain('NOT complete: 1 command block(s) are manual and were not run');
    expect(printed()).toContain('clearproof recipes sample');
    expect(printed()).not.toContain('Recipe complete.');
    output.mockClear();
    mocks.get.mockReturnValue({ ...recipe, body: `${fence}bash:run\necho "hello world"\n${fence}\n` });
    await run(['sample', '--run']);
    expect(printed()).toContain('Recipe complete.');
  });
  it.each([['SIGINT', 130], ['SIGTERM', 143]] as const)(
    'on %s stops the running step\'s process group and exits %i; handlers are removed afterwards', async (signal, code) => {
      const before = process.listenerCount(signal);
      let release = (_: typeof ok) => {};
      mocks.execute.mockReturnValue(new Promise((resolve) => { release = resolve; }));
      const running = run(['sample', '--run']);
      await vi.waitFor(() => expect(mocks.execute).toHaveBeenCalled());
      expect(process.listenerCount(signal)).toBe(before + 1);
      expect(() => process.emit(signal, signal)).toThrow('synthetic exit');
      expect(mocks.killSession).toHaveBeenCalledOnce();
      expect(exit).toHaveBeenCalledWith(code);
      release(ok);
      await running;
      expect(process.listenerCount(signal)).toBe(before);
    });
  it('an interrupt before any shell was opened just exits', async () => {
    let answer = (_: string) => {};
    mocks.question.mockImplementation((_prompt, callback) => { answer = callback; });
    const running = run(['sample', '--run']);
    await vi.waitFor(() => expect(mocks.question).toHaveBeenCalled());
    expect(() => process.emit('SIGINT', 'SIGINT')).toThrow('synthetic exit');
    expect(mocks.killSession).not.toHaveBeenCalled();
    answer('n');
    await running;
  });
});
