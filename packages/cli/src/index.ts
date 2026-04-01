#!/usr/bin/env node
import { Command } from 'commander';
import { demoCommand } from './commands/demo.js';
import { proveCommand } from './commands/prove.js';
import { verifyCommand } from './commands/verify.js';

const pkg = require('../package.json');

const program = new Command();

program
  .name('clearproof')
  .description('ZK Travel Rule Compliance Bridge — proof generation & verification')
  .version(pkg.version);

program.addCommand(demoCommand);
program.addCommand(proveCommand);
program.addCommand(verifyCommand);

program.parse();
