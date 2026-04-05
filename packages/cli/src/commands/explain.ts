import { Command } from 'commander';
import chalk from 'chalk';
import { getSignal, listSignals } from '@clearproof/content';

export const explainCommand = new Command('explain')
  .description('Explain a public circuit signal')
  .argument('<signal>', 'Signal name (e.g. credential_nullifier)')
  .action((signalName: string) => {
    const signal = getSignal(signalName);
    if (!signal) {
      console.error(chalk.red(`Unknown signal: ${signalName}`));
      console.error('');
      console.error('  Available signals:');
      console.error('');
      const signals = listSignals();
      for (const s of signals) {
        console.error(`    ${chalk.dim(`[${s.index}]`)} ${s.name}`);
      }
      console.error('');
      process.exit(1);
    }

    const outputLabel = signal.isOutput ? 'yes (public output)' : 'no (public input)';

    console.log('');
    console.log(
      `  ${chalk.bold.cyan(signal.name)} ${chalk.dim(`(public signal #${signal.index})`)}`,
    );
    console.log('');
    console.log(`  ${signal.description}`);
    console.log('');
    console.log(`  ${chalk.bold('Type:')}      ${signal.type}`);
    console.log(`  ${chalk.bold('Index:')}     ${signal.index}`);
    console.log(`  ${chalk.bold('Output:')}    ${outputLabel}`);
    console.log(`  ${chalk.bold('Source:')}    ${signal.source}`);
    console.log(`  ${chalk.bold('On-chain:')}  ${signal.onChainUsage}`);
    console.log('');
  });
