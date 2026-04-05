import { Command } from 'commander';
import chalk from 'chalk';
import { listTopics, getTopic } from '@clearproof/content';
import { renderMarkdown } from '../render.js';

export const helpCommand = new Command('help')
  .description('Show documentation topics')
  .argument('[topic]', 'Topic slug to display')
  .action((topic?: string) => {
    if (!topic) {
      const topics = listTopics();

      console.log('');
      console.log(chalk.bold.cyan('  Available topics:'));
      console.log('');

      const maxSlug = Math.max(...topics.map((t) => t.slug.length));
      for (const t of topics) {
        console.log(
          `    ${chalk.bold(t.slug.padEnd(maxSlug + 2))} ${chalk.dim(t.title)}`,
        );
      }

      console.log('');
      console.log(`  Usage: ${chalk.dim('clearproof help <topic>')}`);
      console.log('');
      return;
    }

    const entry = getTopic(topic);
    if (!entry) {
      console.error(chalk.red(`Unknown topic: ${topic}`));
      console.error(
        chalk.dim('Run "clearproof help" to see available topics.'),
      );
      process.exit(1);
    }

    console.log('');
    console.log(renderMarkdown(entry.body));
    console.log('');
  });
