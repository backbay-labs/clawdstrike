import { Command } from 'commander';
import { policyCommands } from './commands/policy.js';
import { auditCommands } from './commands/audit.js';

export function registerCli(program: Command): void {
  const clawdstrike = program
    .command('clawdstrike')
    .description('Clawdstrike security management');

  // Policy commands
  const policy = clawdstrike.command('policy').description('Policy management');

  policy
    .command('lint <file>')
    .description('Validate a policy file')
    .action(policyCommands.lint);

  policy
    .command('show')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Show the current effective policy')
    .action((options) => policyCommands.show(options));

  policy
    .command('test <event-file>')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Test an event against the current policy')
    .action((eventFile, options) => policyCommands.test(eventFile, options));

  policy
    .command('diff <file1> <file2>')
    .description('Compare two policy files')
    .action(policyCommands.diff);

  // Audit commands
  const audit = clawdstrike.command('audit').description('Audit log management');

  audit
    .command('query')
    .option('-s, --since <time>', 'Start time (ISO format)')
    .option('-g, --guard <name>', 'Filter by guard')
    .option('-d, --denied', 'Only show denied events')
    .description('Query the audit log')
    .action((options) => auditCommands.query(options));

  audit
    .command('export <file>')
    .description('Export audit log to file')
    .action((file, options) => auditCommands.export(file, options));

  // Quick commands
  clawdstrike
    .command('why <event-id>')
    .description('Explain why an event was blocked')
    .action((eventId, options) => auditCommands.explain(eventId, options));
}

export function createCli(): Command {
  const program = new Command();
  program
    .name('clawdstrike')
    .description('Clawdstrike security CLI')
    .version('0.1.0');

  // Register commands directly on root
  const policy = program.command('policy').description('Policy management');

  policy
    .command('lint <file>')
    .description('Validate a policy file')
    .action(policyCommands.lint);

  policy
    .command('show')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Show the current effective policy')
    .action((options) => policyCommands.show(options));

  policy
    .command('test <event-file>')
    .option('-p, --policy <path>', 'Policy file path')
    .description('Test an event against the current policy')
    .action((eventFile, options) => policyCommands.test(eventFile, options));

  policy
    .command('diff <file1> <file2>')
    .description('Compare two policy files')
    .action(policyCommands.diff);

  const audit = program.command('audit').description('Audit log management');

  audit
    .command('query')
    .option('-s, --since <time>', 'Start time')
    .option('-g, --guard <name>', 'Filter by guard')
    .option('-d, --denied', 'Only show denied events')
    .description('Query the audit log')
    .action((options) => auditCommands.query(options));

  audit
    .command('export <file>')
    .description('Export audit log to file')
    .action((file, options) => auditCommands.export(file, options));

  program
    .command('why <event-id>')
    .description('Explain why an event was blocked')
    .action((eventId, options) => auditCommands.explain(eventId, options));

  return program;
}
