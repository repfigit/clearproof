import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ShellSession } from '../src/shell-session.js';

const sessions: ShellSession[] = [];
function open(options?: ConstructorParameters<typeof ShellSession>[0]): ShellSession {
  const session = new ShellSession(options);
  sessions.push(session);
  return session;
}
afterEach(() => { for (const session of sessions.splice(0)) session.close(); });

describe('recipe shell session (real bash)', () => {
  it('keeps cd and export from one step for the next', async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'clearproof-recipe-')));
    const session = open();
    expect(session.ended).toBe(false);
    expect(await session.run(`cd '${dir}'`)).toEqual({ stdout: '', stderr: '', code: 0, stopped: null, sessionEnded: false });
    expect((await session.run('export CLEARPROOF_RECIPE_TEST="two words"')).code).toBe(0);
    const result = await session.run('pwd\necho "$CLEARPROOF_RECIPE_TEST" \\\n  again');
    expect(result).toEqual({ stdout: `${dir}\ntwo words again\n`, stderr: '', code: 0, stopped: null, sessionEnded: false });
    fs.rmSync(dir, { recursive: true });
  });

  it('reports the exit status and stderr of a failed step and keeps the session', async () => {
    const session = open();
    const failed = await session.run('printf partial; echo problem >&2; false');
    expect(failed).toEqual({ stdout: 'partial', stderr: 'problem\n', code: 1, stopped: null, sessionEnded: false });
    const syntax = await session.run('if then');
    expect(syntax.code).not.toBe(0);
    expect(syntax.stderr).toContain('syntax error');
    expect(syntax.sessionEnded).toBe(false);
    expect((await session.run('(exit 7)')).code).toBe(7);
    expect((await session.run('echo still here')).stdout).toBe('still here\n');
  });

  it('gives steps no terminal input, so a step cannot consume later steps', async () => {
    const session = open();
    expect(await session.run('cat; echo "read finished"')).toMatchObject({ stdout: 'read finished\n', code: 0 });
    expect((await session.run('echo next')).stdout).toBe('next\n');
  });

  it('rejects overlapping steps', async () => {
    const session = open();
    const first = session.run('echo one');
    expect(() => session.run('echo two')).toThrow('A recipe step is already running');
    expect((await first).stdout).toBe('one\n');
  });

  it('reports a step that ends the shell and refuses further steps', async () => {
    const session = open();
    const result = await session.run('echo leaving; exit 3');
    expect(result).toEqual({ stdout: 'leaving\n', stderr: '', code: 3, stopped: null, sessionEnded: true });
    expect(session.ended).toBe(true);
    expect(await session.run('echo unreachable')).toEqual({ stdout: '', stderr: '', code: 127, stopped: null, sessionEnded: true });
  });

  it('kills a step and everything it started when the time limit passes', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clearproof-recipe-'));
    const pidFile = path.join(dir, 'pid');
    const session = open({ timeoutMs: 400 });
    const result = await session.run(`trap '' TERM; echo started; sleep 30 & echo $! > '${pidFile}'; wait`);
    expect(result).toMatchObject({ stdout: 'started\n', code: 124, stopped: 'timeout', sessionEnded: true });
    await session.closed;
    const pid = Number(fs.readFileSync(pidFile, 'utf8'));
    expect(pid).toBeGreaterThan(1);
    expect(() => process.kill(pid, 0)).toThrow();
    fs.rmSync(dir, { recursive: true });
  });

  it('stops a step that exceeds the output limit on either stream', async () => {
    const out = await open({ maxOutput: 64 }).run('yes clearproof');
    expect(out).toMatchObject({ code: 126, stopped: 'output-limit', sessionEnded: true });
    expect(out.stdout.length).toBe(64);
    const err = await open({ maxOutput: 64 }).run('yes clearproof >&2');
    expect(err).toMatchObject({ stdout: '', code: 126, stopped: 'output-limit', sessionEnded: true });
    expect(err.stderr.length).toBe(64);
  });

  it('reports a shell that cannot start', async () => {
    const session = open({ shell: '/nonexistent/clearproof-shell' });
    const result = await session.run('echo never');
    expect(result).toMatchObject({ stdout: '', code: 127, stopped: null, sessionEnded: true });
    expect(result.stderr).toContain('Could not start the recipe shell');
    await session.closed;
    expect((await session.run('echo never')).stderr).toContain('Could not start the recipe shell');
  });

  it('survives a broken input pipe: the step settles when the shell closes', async () => {
    const session = open();
    const stdin = (session as unknown as { child: { stdin: NodeJS.WritableStream } }).child.stdin;
    const result = session.run('kill -9 $$');
    stdin.emit('error', Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }));
    expect(await result).toMatchObject({ code: 1, stopped: null, sessionEnded: true });
  });

  it('refuses steps after close', async () => {
    const session = open();
    session.close();
    await session.closed;
    expect((await session.run('echo late')).code).toBe(127);
  });
});
