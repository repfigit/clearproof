#!/usr/bin/env node
import { Command } from 'commander';
import { authorizeCurrentCommand } from './commands/authorize-current.js';
import { observationCommand } from './commands/observation.js';
import { inspectCurrentCommand } from './commands/inspect-current.js';
import { investigationCommand } from './commands/investigation.js';
import { policyCommand } from './commands/policy.js';
import { demoCommand } from './commands/demo.js';
import { proveCommand } from './commands/prove.js';
import { verifyHistoryCommand } from './commands/verify-history.js';
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

program.addCommand(authorizeCurrentCommand);
program.addCommand(observationCommand);
program.addCommand(inspectCurrentCommand);
program.addCommand(investigationCommand);
program.addCommand(policyCommand);
program.addCommand(demoCommand);
program.addCommand(proveCommand);
program.addCommand(verifyCommand);
program.addCommand(verifyHistoryCommand);
program.addCommand(helpCommand);
program.addCommand(recipesCommand);
program.addCommand(explainCommand);

void program.parseAsync();
