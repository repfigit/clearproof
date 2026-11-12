import { spawn, type ChildProcess } from 'child_process';
import { randomBytes } from 'crypto';

export interface StepResult {
  stdout: string;
  stderr: string;
  /** Exit status of the step. 124 after a timeout, 126 after the output limit, 127 if bash could not start. */
  code: number;
  /** Set when the step was stopped; the session cannot run further steps. */
  stopped: 'timeout' | 'output-limit' | null;
  /** True when the shell is gone (stopped, exited or never started), so `cd`/`export` state is lost. */
  sessionEnded: boolean;
}

export interface ShellSessionOptions {
  /** Per-step limit in milliseconds. */
  timeoutMs?: number;
  /** Per-stream captured output limit in characters. */
  maxOutput?: number;
  /** Shell executable. Recipes are written for bash. */
  shell?: string;
}

interface Pending {
  out: string;
  err: string;
  status: number | null;
  errDone: boolean;
  timer: NodeJS.Timeout;
  resolve: (result: StepResult) => void;
}

/**
 * One bash process that runs recipe steps in sequence, so a `cd` or `export`
 * in one step is still in effect for the next.
 *
 * Each step is sent as a quoted here-document and run with `eval`, with its
 * stdin set to /dev/null so a step cannot read the commands that follow it.
 * A random marker printed after the step carries its exit status. The shell
 * runs in its own process group; a step that exceeds the time or output limit
 * has the whole group killed, including anything the step started.
 */
export class ShellSession {
  private readonly child: ChildProcess;
  private readonly marker = `__clearproof_step_${randomBytes(16).toString('hex')}__`;
  private readonly timeoutMs: number;
  private readonly maxOutput: number;
  private pending: Pending | null = null;
  private failure = '';
  private isEnded = false;
  /** Resolves when the shell has exited and its output streams are closed. */
  readonly closed: Promise<void>;

  constructor(options: ShellSessionOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.maxOutput = options.maxOutput ?? 1024 * 1024;
    this.child = spawn(options.shell ?? 'bash', ['--noprofile', '--norc'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: true,
    });
    this.closed = new Promise((resolve) => {
      const finish = (code: number) => {
        this.isEnded = true;
        this.settle(code, null);
        resolve();
      };
      this.child.once('error', (error) => {
        this.failure = `Could not start the recipe shell: ${error.message}\n`;
        finish(127);
      });
      this.child.once('close', (code) => finish(code ?? 1));
    });
    // A write to a shell that has already exited reports EPIPE here; the 'close' handler settles the step.
    this.child.stdin!.on('error', () => {});
    this.child.stdout!.setEncoding('utf8').on('data', (chunk: string) => this.collect('out', chunk));
    this.child.stderr!.setEncoding('utf8').on('data', (chunk: string) => this.collect('err', chunk));
  }

  /** True once the shell can no longer run steps. */
  get ended(): boolean {
    return this.isEnded;
  }

  /** Run one step in the session. Steps must be run one at a time. */
  run(command: string): Promise<StepResult> {
    if (this.pending) throw new Error('A recipe step is already running');
    return new Promise((resolve) => {
      if (this.isEnded) {
        resolve({ stdout: '', stderr: this.failure, code: 127, stopped: null, sessionEnded: true });
        return;
      }
      const timer = setTimeout(() => this.stop('timeout', 124), this.timeoutMs);
      this.pending = { out: '', err: '', status: null, errDone: false, timer, resolve };
      const m = this.marker;
      this.child.stdin!.write(
        `IFS= read -r -d '' __clearproof_step <<'${m}'\n${command}\n${m}\n` +
        'eval "$__clearproof_step" </dev/null\n' +
        '__clearproof_status=$?\n' +
        `printf '\\n%s %s\\n' '${m}' "$__clearproof_status"\n` +
        `printf '\\n%s\\n' '${m}' >&2\n`,
      );
    });
  }

  /** End the session. Processes a step left in the background are not stopped. */
  close(): void {
    this.isEnded = true;
    this.child.stdin!.end();
    this.child.stdout!.destroy();
    this.child.stderr!.destroy();
    this.child.unref();
  }

  /** Stop the shell and everything a step started. Used when the CLI itself is interrupted. */
  kill(): void {
    this.isEnded = true;
    try { process.kill(-this.child.pid!, 'SIGKILL'); } catch { /* the group has already exited */ }
  }

  private collect(stream: 'out' | 'err', chunk: string): void {
    const pending = this.pending;
    if (!pending) return;
    pending[stream] += chunk;
    if (stream === 'out') {
      const match = new RegExp(`\\n${this.marker} (\\d+)\\n`).exec(pending.out);
      if (match) {
        pending.status = Number(match[1]);
        pending.out = pending.out.slice(0, match.index);
      }
    } else {
      const index = pending.err.indexOf(`\n${this.marker}\n`);
      if (index !== -1) {
        pending.errDone = true;
        pending.err = pending.err.slice(0, index);
      }
    }
    if (pending.status !== null && pending.errDone) this.settle(pending.status, null);
    else if (pending[stream].length > this.maxOutput) this.stop('output-limit', 126);
  }

  private stop(reason: 'timeout' | 'output-limit', code: number): void {
    this.isEnded = true;
    // Negative pid: the whole process group, so programs started by the step stop too.
    try { process.kill(-this.child.pid!, 'SIGKILL'); } catch { /* the group has already exited */ }
    this.settle(code, reason);
  }

  private settle(code: number, stopped: StepResult['stopped']): void {
    const pending = this.pending;
    if (!pending) return;
    this.pending = null;
    clearTimeout(pending.timer);
    pending.resolve({
      stdout: pending.out.slice(0, this.maxOutput),
      stderr: this.failure + pending.err.slice(0, this.maxOutput),
      code,
      stopped,
      sessionEnded: this.isEnded,
    });
  }
}
