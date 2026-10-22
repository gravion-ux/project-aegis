#!/usr/bin/env node
'use strict';

/**
 * `aegis` command-line entry point.
 *
 * Examples:
 *   aegis status
 *   aegis agents list
 *   aegis tasks create --title "audit headers" --role classifier --goal "Check HSTS and CSP"
 *   aegis tasks run <id>
 *   aegis tasks list
 *   aegis tasks show <id>
 *   aegis tasks cancel <id>
 *   aegis memory search <query>
 *   aegis doctor
 *   aegis --help
 *
 * Exit codes:
 *   0 — success
 *   1 — runtime / agent error
 *   2 — usage error
 */

const path = require('node:path');
const { createContext, dispatch, help } = require('./index');

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(help() + '\n');
    return 0;
  }

  // multi-word command: tasks create | tasks run | tasks show | tasks cancel | tasks list
  // agents list | memory search
  // Honour --root to override the workspace root; default to the
  // current working directory so tests can isolate themselves.
  let root = process.cwd();
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--root' && argv[i + 1]) {
      root = path.resolve(argv[i + 1]);
      argv.splice(i, 2);
      i -= 1;
    }
  }
  const ctx = createContext({ root, argv });
  // The structured logger writes JSON lines — point it at stderr so it
  // does not collide with the command's JSON result on stdout.
  ctx.logger.stream = process.stderr;

  let command;
  const two = argv[0] === 'providers' ? argv[1]
    : argv[0] === 'tools' ? argv[1]
    : argv[0] === 'config' ? argv[1]
    : argv[0] === 'security' && argv[1] === 'scope' ? 'scope'
    : null;
  if (two) command = `${argv[0]} ${two}`;
  else if (argv[0] === 'agents' && argv[1] === 'list') command = 'agents list';
  else if (argv[0] === 'tasks' && argv[1] === 'list') command = 'tasks list';
  else if (argv[0] === 'tasks' && argv[1] === 'create') command = 'tasks create';
  else if (argv[0] === 'tasks' && argv[1] === 'run') command = 'tasks run';
  else if (argv[0] === 'tasks' && argv[1] === 'show') command = 'tasks show';
  else if (argv[0] === 'tasks' && argv[1] === 'cancel') command = 'tasks cancel';
  else if (argv[0] === 'memory' && argv[1] === 'search') command = 'memory search';
  else command = argv[0];

  // strip the command tokens from argv before passing to handler
  if (command !== argv[0]) {
    ctx.argv = argv.slice(command.split(' ').length);
  }

  const result = await dispatch(command, ctx);
  process.stdout.write(JSON.stringify(result.output, null, 2) + '\n');
  ctx.audit.close();
  return result.code;
}

main().then((code) => process.exit(typeof code === 'number' ? code : 0))
  .catch((err) => {
    process.stderr.write(`fatal: ${err && err.message ? err.message : err}\n`);
    process.exit(1);
  });
