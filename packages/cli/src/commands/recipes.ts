import { Command } from 'commander';
import chalk from 'chalk';
import { createInterface } from 'readline';
import { execFile } from 'child_process';
import { listRecipes, getRecipe } from '@clearproof/content';
import { renderMarkdown } from '../render.js';

function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function runCommand(command: string): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    // Split the command into program + args for execFile (no shell injection)
    const parts = command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
    const prog = parts[0];
    const args = parts.slice(1).map((a) => a.replace(/^["']|["']$/g, ''));

    execFile(prog!, args, { timeout: 60_000 }, (error: Error | null, stdout: string, stderr: string) => {
      resolve({
        stdout: stdout?.toString() ?? '',
        stderr: stderr?.toString() ?? '',
        code: error ? (error as NodeJS.ErrnoException).code ? 1 : 1 : 0,
      });
    });
  });
}

export const recipesCommand = new Command('recipes')
  .description('Browse and run step-by-step recipes')
  .argument('[name]', 'Recipe slug to display or run')
  .option('--run', 'Execute recipe steps interactively')
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

    for (let i = 0; i < recipe.steps.length; i++) {
      const step = recipe.steps[i];
      console.log(chalk.bold.white(`  ## Step ${i + 1}: ${step.description}`));
      console.log('');
      console.log(`  ${chalk.dim('>')} ${chalk.dim(step.command)}`);
      console.log('');

      const answer = await prompt(`  Run this step? ${chalk.dim('[Y/n]')} `);
      if (answer.toLowerCase() === 'n') {
        console.log(chalk.yellow('  Skipped.'));
        console.log('');
        continue;
      }

      const result = await runCommand(step.command);
      if (result.stdout) {
        console.log(chalk.dim(result.stdout));
      }
      if (result.stderr) {
        console.error(chalk.yellow(result.stderr));
      }
      if (result.code !== 0) {
        console.error(
          chalk.red(`  Step failed with exit code ${result.code}`),
        );
        const cont = await prompt(`  Continue anyway? ${chalk.dim('[y/N]')} `);
        if (cont.toLowerCase() !== 'y') {
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

    console.log(chalk.bold.green('  Recipe complete.'));
    console.log('');
  });
