'use strict';

/**
 * Command router and dispatch.
 *
 * Commands are small, JSON-serializable, and easy to test.
 * Every command returns `{ code, output }` where `code` is an integer
 * suitable for `process.exit`.
 *
 * The router is intentionally not clever: each command receives a
 * parsed context with the Storage, the Audit log, the Logger, and the
 * AgentRegistry, plus positional args and flags.
 */

const { Task } = require('./task');
const { STATES, isTerminal } = require('./states');

const COMMANDS = {
  status: {
    help: 'aegis status  â€” show system status and counts',
    handler: (ctx) => {
      const tasks = ctx.storage.list();
      const byState = {};
      for (const t of tasks) byState[t.state] = (byState[t.state] || 0) + 1;
      return { code: 0, output: { taskCount: tasks.length, byState, agents: ctx.agentRegistry.list() } };
    },
  },

  'agents list': {
    help: 'aegis agents list  â€” list registered agent roles',
    handler: (ctx) => ({ code: 0, output: { agents: ctx.agentRegistry.list() } }),
  },

  'tasks list': {
    help: 'aegis tasks list  â€” list all tasks',
    handler: (ctx) => ({ code: 0, output: { tasks: ctx.storage.list() } }),
  },

  'tasks show': {
    help: 'aegis tasks show <id>  â€” show a single task by id',
    handler: (ctx, args) => {
      const id = args[0];
      if (!id) return { code: 2, output: { error: 'task id required' } };
      const t = ctx.storage.get(id);
      if (!t) return { code: 2, output: { error: `no such task: ${id}` } };
      return { code: 0, output: t };
    },
  },

  'tasks create': {
    help: 'aegis tasks create --title <t> --role <r> --goal <g>  â€” create a new task',
    handler: (ctx, args, flags) => {
      const title = flags.title || args[0] || '(untitled)';
      const role = flags.role || 'coding';
      const goal = flags.goal || '';
      if (!ctx.agentRegistry.get(role)) {
        return { code: 2, output: { error: `unknown role: ${role}` } };
      }
      const t = new Task({ title, role, goal });
      t.transition(STATES.READY, { actor: 'user' });
      ctx.storage.put(t);
      ctx.audit.append({ kind: 'task.create', taskId: t.id, role, title });
      ctx.logger.info('task created', { taskId: t.id, role });
      return { code: 0, output: t.toJSON() };
    },
  },

  'tasks run': {
    help: 'aegis tasks run <id>  â€” execute a queued task',
    handler: async (ctx, args) => {
      const id = args[0];
      if (!id) return { code: 2, output: { error: 'task id required' } };
      const t = Task.fromJSON(ctx.storage.get(id));
      if (!t) return { code: 2, output: { error: `no such task: ${id}` } };
      if (isTerminal(t.state)) {
        return { code: 2, output: { error: `task is in terminal state: ${t.state}` } };
      }
      const agent = ctx.agentRegistry.get(t.role);
      if (!agent) return { code: 2, output: { error: `no agent for role: ${t.role}` } };
      t.transition(STATES.RUNNING, { actor: 'runtime' });
      ctx.storage.put(t);
      ctx.audit.append({ kind: 'task.run.start', taskId: t.id });
      try {
        const result = await agent.run(t, {});
        t.attachOutput(result.output);
        for (const ev of (result.evidence || [])) t.addEvidence(ev);
        t.transition(result.status, { actor: 'agent', error: result.error });
        ctx.storage.put(t);
        ctx.audit.append({ kind: 'task.run.end', taskId: t.id, status: result.status });
        ctx.logger.info('task complete', { taskId: t.id, status: result.status });
        return { code: result.status === STATES.SUCCEEDED ? 0 : 1, output: t.toJSON() };
      } catch (err) {
        t.transition(STATES.FAILED, { actor: 'runtime', error: String(err && err.message || err) });
        ctx.storage.put(t);
        ctx.audit.append({ kind: 'task.run.error', taskId: t.id, error: String(err && err.message || err) });
        ctx.logger.error('task failed', { taskId: t.id, error: String(err && err.message || err) });
        return { code: 1, output: { error: String(err && err.message || err) } };
      }
    },
  },

  'tasks cancel': {
    help: 'aegis tasks cancel <id>  â€” cancel a non-terminal task',
    handler: (ctx, args) => {
      const id = args[0];
      if (!id) return { code: 2, output: { error: 'task id required' } };
      const t = Task.fromJSON(ctx.storage.get(id));
      if (!t) return { code: 2, output: { error: `no such task: ${id}` } };
      if (isTerminal(t.state)) {
        return { code: 2, output: { error: `task already terminal: ${t.state}` } };
      }
      t.transition(STATES.CANCELLED, { actor: 'user', note: 'cancelled by operator' });
      ctx.storage.put(t);
      ctx.audit.append({ kind: 'task.cancel', taskId: t.id });
      ctx.logger.warn('task cancelled', { taskId: t.id });
      return { code: 0, output: t.toJSON() };
    },
  },

  'memory search': {
    help: 'aegis memory search <query>  â€” substring search across memory files',
    handler: async (ctx, args) => {
      const q = (args[0] || '').toLowerCase();
      if (!q) return { code: 2, output: { error: 'query required' } };
      const mem = await ctx.memory.search(q);
      return { code: 0, output: { matches: mem } };
    },
  },

  doctor: {
    help: 'aegis doctor  â€” check workspace integrity',
    handler: async (ctx) => {
      const doctorAgent = ctx.agentRegistry.get('doctor');
      if (!doctorAgent) return { code: 2, output: { error: 'no doctor agent' } };
      const t = new Task({ role: 'doctor', title: 'doctor', input: { root: ctx.root } });
      t.transition(STATES.READY, { actor: 'user' });
      t.transition(STATES.RUNNING, { actor: 'runtime' });
      const result = await doctorAgent.run(t, {});
      t.attachOutput(result.output);
      t.transition(STATES.SUCCEEDED, { actor: 'agent' });
      return { code: 0, output: result.output };
    },
  },

  // ---- Phase 2 commands ----

  'providers list': {
    help: 'aegis providers list  â€” list registered providers and the active default',
    handler: (ctx) => ({
      code: 0,
      output: {
        default: ctx.config.provider.default,
        allowPaid: ctx.config.provider.allowPaid,
        registered: ctx.providerRegistry.list(),
        envConfigured: {
          AEGIS_LLM_URL: !!(ctx.options.env || process.env).AEGIS_LLM_URL,
          AEGIS_LLM_AUTH_HEADER: !!(ctx.options.env || process.env).AEGIS_LLM_AUTH_HEADER,
        },
      },
    }),
  },

  'providers smoke': {
    help: 'aegis providers smoke [--model <m>]  â€” send one test prompt to the routed provider',
    handler: async (ctx, args, flags) => {
      const model = flags.model || ctx.config.provider.default;
      try {
        const p = ctx.providerRouter.resolve(model);
        const r = await p.complete({
          messages: [{ role: 'user', content: 'ping' }],
        });
        ctx.audit.append({ kind: 'provider.smoke', model: p.name || p.model });
        return { code: 0, output: { provider: p.name || 'http', model, ok: true, preview: String(r.text).slice(0, 200), usage: p.usage() } };
      } catch (err) {
        ctx.audit.append({ kind: 'provider.smoke.error', model, error: String(err && err.message || err) });
        return { code: 1, output: { provider: 'unknown', model, ok: false, error: String(err && err.message || err) } };
      }
    },
  },

  'tools list': {
    help: 'aegis tools list  â€” list every registered tool with its risk level',
    handler: (ctx) => {
      const names = ctx.toolRegistry.list();
      const rows = names.map((n) => {
        const t = ctx.toolRegistry.get(n);
        return { name: t.name, riskLevel: t.riskLevel, requiredPermissions: t.requiredPermissions, purpose: t.purpose };
      });
      return { code: 0, output: { tools: rows } };
    },
  },

  'tools describe': {
    help: 'aegis tools describe <name>  â€” show one tool declaration',
    handler: (ctx, args) => {
      const name = args[0];
      if (!name) return { code: 2, output: { error: 'tool name required' } };
      const t = ctx.toolRegistry.get(name);
      if (!t) return { code: 2, output: { error: `tool not registered: ${name}` } };
      return {
        code: 0,
        output: { name: t.name, purpose: t.purpose, riskLevel: t.riskLevel, requiredPermissions: t.requiredPermissions, inputSchema: t.inputSchema, maxDurationMs: t.maxDurationMs, maxOutputBytes: t.maxOutputBytes },
      };
    },
  },

  usage: {
    help: 'aegis usage  â€” show the configured limits and current usage',
    handler: (ctx) => ({ code: 0, output: { summary: ctx.budgets.summary(), limits: ctx.config.budget } }),
  },

  'security scope': {
    help: 'aegis security scope  â€” show the local assessment scope (loopback only by default)',
    handler: (ctx) => ({
      code: 0,
      output: {
        loopbackOnly: true,
        allowedRoots: ['<workspace>/data', '<workspace>/state'],
        denyByDefault: true,
        note: 'Tools are default-deny. Each task must list allowedTools explicitly. Non-loopback HTTP requires the http.external tool and an explicit allowlist entry.',
      },
    }),
  },

  'config show': {
    help: 'aegis config show  â€” print the effective configuration (secrets stripped)',
    handler: (ctx) => ({ code: 0, output: ctx.config }),
  },
};

function parseArgs(argv) {
  // split flags (--k=v or --k v) from positional
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const k = a.slice(2);
        const v = argv[i + 1];
        if (v != null && !v.startsWith('--')) {
          flags[k] = v;
          i += 1;
        } else {
          flags[k] = true;
        }
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

async function dispatch(commandPath, ctx) {
  const cmd = COMMANDS[commandPath];
  if (!cmd) {
    return { code: 2, output: { error: `unknown command: ${commandPath}` } };
  }
  const { positional, flags } = parseArgs(ctx.argv || []);
  const result = await cmd.handler(ctx, positional, flags);
  return result;
}

function help() {
  const lines = ['aegis â€” Project AEGIS command-line interface', ''];
  for (const [name, def] of Object.entries(COMMANDS)) {
    lines.push(`  ${def.help}`);
  }
  return lines.join('\n');
}

module.exports = { COMMANDS, dispatch, parseArgs, help };
