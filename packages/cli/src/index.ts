#!/usr/bin/env node
import { Command } from 'commander';
import { demoCommand } from './commands/demo.js';
import { proveCommand } from './commands/prove.js';
import { verifyCommand } from './commands/verify.js';

const program = new Command();

program
  .name('clearproof')
  .description('ZK Travel Rule Compliance Bridge — proof generation & verification')
  .version('0.1.0');

program.addCommand(demoCommand);
program.addCommand(proveCommand);
program.addCommand(verifyCommand);

program.parse();
