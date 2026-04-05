#!/usr/bin/env node
import { Command } from 'commander';
import { demoCommand } from './commands/demo.js';
import { proveCommand } from './commands/prove.js';
import { verifyCommand } from './commands/verify.js';
import { helpCommand } from './commands/help.js';
import { recipesCommand } from './commands/recipes.js';
import { explainCommand } from './commands/explain.js';

const pkg = require('../package.json');

const program = new Command();

program
  .name('clearproof')
  .description('ZK Travel Rule Compliance Bridge — proof generation & verification')
  .version(pkg.version);

program.addCommand(demoCommand);
program.addCommand(proveCommand);
program.addCommand(verifyCommand);
program.addCommand(helpCommand);
program.addCommand(recipesCommand);
program.addCommand(explainCommand);

program.parse();
