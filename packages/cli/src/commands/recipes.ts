import { Command } from 'commander';
import chalk from 'chalk';
import { createInterface } from 'readline';
import { listRecipes, getRecipe } from '@clearproof/content';
import { renderMarkdown } from '../render.js';
import { ShellSession } from '../shell-session.js';

const STEP_TIMEOUT_MS = 60_000;

/** Fenced code blocks in the recipe that --run does not execute (plain fences, not `bash:run`). */
function manualBlockCount(body: string, runnableSteps: number): number {
  const fences = body.split('\n').filter((line) => line.startsWith('```')).length;
  return Math.max(0, Math.floor(fences / 2) - runnableSteps);
}

/** Ask one question. Resolves null when input closes without an answer, which is never consent. */
function prompt(question: string): Promise<string | null> {
  // A new interface on input that has already ended would never emit 'close'.
  if (process.stdin.readableEnded) return Promise.resolve(null);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.once('close', () => resolve(null));
    rl.question(question, (answer) => {
      // Resolve before close(): close() emits 'close' synchronously.
      resolve(answer.trim());
      rl.close();
    });
  });
}

export const recipesCommand = new Command('recipes')
  .description('Browse step-by-step recipes; --run executes one in a local bash session after per-step confirmation')
  .argument('[name]', 'Recipe slug to display or run')
  .option('--run', 'Execute the recipe steps in one bash session, asking before each step (60 s limit per step; steps get no terminal input)')
  .action(async (name?: string, opts?: { run?: boolean }) => {
    if (!name) {
      const recipes = listRecipes();

      console.log('');
      console.log(chalk.bold.cyan('  Available recipes:'));
      console.log('');

      const maxSlug = Math.max(...recipes.map((r) => r.slug.length));
      for (const r of recipes) {
        console.log(
          `    ${chalk.bold(r.slug.padEnd(maxSlug + 2))} ${r.title} ${chalk.dim(`(${r.estimatedTime})`)}`,
        );
      }

      console.log('');
      console.log(`  Usage: ${chalk.dim('clearproof recipes <name>')}`);
      console.log(`         ${chalk.dim('clearproof recipes <name> --run')}   (execute interactively)`);
      console.log('');
      return;
    }

    const recipe = getRecipe(name);
    if (!recipe) {
      console.error(chalk.red(`Unknown recipe: ${name}`));
      console.error(
        chalk.dim('Run "clearproof recipes" to see available recipes.'),
      );
      process.exit(1);
    }

    if (!opts?.run) {
      console.log('');
      console.log(renderMarkdown(recipe.body));
      console.log('');
      return;
    }

    // --- Interactive execution ---
    console.log('');
    console.log(chalk.bold.cyan(`# ${recipe.title}`));
    console.log('');

    if (recipe.prereqs.length > 0) {
      console.log(chalk.dim(`  Prereqs: ${recipe.prereqs.join(', ')}`));
      console.log('');
    }

    console.log(chalk.dim('  Steps run in one bash session from the current directory, so cd and export carry over.'));
    console.log(chalk.dim('  Each step is limited to 60 seconds and cannot read from the terminal.'));
    console.log('');

    let session: ShellSession | null = null;
    // The shell runs in its own process group so a timeout can stop everything a step
    // started. That also means Ctrl+C does not reach it, so stop it explicitly.
    const interrupted = (signal: NodeJS.Signals) => {
      session?.kill();
      process.exit(signal === 'SIGINT' ? 130 : 143);
    };
    process.once('SIGINT', interrupted);
    process.once('SIGTERM', interrupted);
    try {
      for (let i = 0; i < recipe.steps.length; i++) {
        const step = recipe.steps[i];
        console.log(chalk.bold.white(`  ## Step ${i + 1}: ${step.description}`));
        console.log('');
        for (const line of step.command.split('\n')) {
          console.log(`  ${chalk.dim('>')} ${chalk.dim(line)}`);
        }
        console.log('');

        const answer = await prompt(`  Run this step? ${chalk.dim('[Y/n]')} `);
        if (answer === null) {
          console.error(chalk.red('  Input closed before an answer. Stopping; this step was not run.'));
          process.exit(1);
        }
        if (answer.toLowerCase() === 'n') {
          console.log(chalk.yellow('  Skipped.'));
          console.log('');
          continue;
        }

        let result;
        if (step.command.trim() === '') {
          result = { stdout: '', stderr: '', code: 2, stopped: null, sessionEnded: false };
          console.error(chalk.red('  This step has no command.'));
        } else {
          if (session?.ended) {
            session.close();
            session = null;
            console.log(chalk.yellow('  Starting a new shell. Earlier cd and export commands are not carried over.'));
          }
          session ??= new ShellSession({ timeoutMs: STEP_TIMEOUT_MS });
          result = await session.run(step.command);
        }
        if (result.stdout) {
          console.log(chalk.dim(result.stdout));
        }
        if (result.stderr) {
          console.error(chalk.yellow(result.stderr));
        }
        if (result.code !== 0) {
          if (result.stopped === 'timeout') {
            console.error(chalk.red(`  Step stopped after the ${STEP_TIMEOUT_MS / 1000} second limit`));
          } else if (result.stopped === 'output-limit') {
            console.error(chalk.red('  Step stopped after exceeding the output limit'));
          } else {
            console.error(chalk.red(`  Step failed with exit code ${result.code}`));
          }
          const cont = await prompt(`  Continue anyway? ${chalk.dim('[y/N]')} `);
          if (cont?.toLowerCase() !== 'y') {
            process.exit(1);
          }
        } else {
          console.log(chalk.green('  OK'));
        }

        if (step.expected) {
          console.log(chalk.dim(`  Expected: ${step.expected}`));
        }
        console.log('');
      }
    } finally {
      process.removeListener('SIGINT', interrupted);
      process.removeListener('SIGTERM', interrupted);
      session?.close();
    }

    const manual = manualBlockCount(recipe.body, recipe.steps.length);
    if (manual > 0) {
      console.log(chalk.bold.yellow(`  Runnable steps finished. This recipe is NOT complete: ${manual} command block(s) are manual and were not run.`));
      console.log(chalk.dim(`  Read them with: clearproof recipes ${name}`));
    } else {
      console.log(chalk.bold.green('  Recipe complete.'));
    }
    console.log('');
  });
