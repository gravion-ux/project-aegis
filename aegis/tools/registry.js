'use strict';

/**
 * Tool registry and permission policy.
 *
 * Each tool declares:
 *   - name, purpose, inputSchema, requiredPermissions, riskLevel
 *
 * Risk levels: 'read' | 'mutate' | 'external' | 'destructive'.
 *
 * Authorization is enforced in the execution layer, never in a
 * prompt. Tools are default-deny: a tool must be explicitly
 * registered AND the calling task must include it in its
 * `allowedTools` list.
 *
 * Every call records audit events: tool.call.start, tool.call.end,
 * tool.call.error, tool.deny.
 */

const { audit } = (() => {
  // late-binding: the Audit instance is passed in via ToolRegistry.run()
  return { audit: null };
})();

class ToolError extends Error {
  constructor(message, { code = 'TOOL_ERROR', retryable = false, cause = null } = {}) {
    super(message);
    this.name = 'ToolError';
    this.code = code;
    this.retryable = retryable;
    this.cause = cause;
  }
}

class ToolDeniedError extends ToolError {
  constructor(name, reason) {
    super(`tool "${name}" denied: ${reason}`, { code: 'TOOL_DENIED' });
    this.name = 'ToolDeniedError';
  }
}

class ToolNotFoundError extends ToolError {
  constructor(name) {
    super(`tool "${name}" not registered`, { code: 'TOOL_NOT_FOUND' });
    this.name = 'ToolNotFoundError';
  }
}

const RISK = Object.freeze({
  READ:        'read',
  MUTATE:      'mutate',
  EXTERNAL:    'external',
  DESTRUCTIVE: 'destructive',
});

const RISK_RANK = { read: 1, mutate: 2, external: 3, destructive: 4 };

class Tool {
  constructor({ name, purpose, inputSchema, requiredPermissions = [], riskLevel = 'read',
                maxDurationMs = 10_000, maxOutputBytes = 1024 * 1024, run }) {
    if (!name) throw new Error('Tool: name required');
    if (typeof run !== 'function') throw new Error(`Tool ${name}: run must be a function`);
    if (!RISK[riskLevel.toUpperCase()]) throw new Error(`Tool ${name}: unknown riskLevel ${riskLevel}`);
    this.name = name;
    this.purpose = purpose || '';
    this.inputSchema = inputSchema || { type: 'object' };
    this.requiredPermissions = Array.isArray(requiredPermissions) ? requiredPermissions : [];
    this.riskLevel = String(riskLevel).toLowerCase();
    this.maxDurationMs = maxDurationMs;
    this.maxOutputBytes = maxOutputBytes;
    this.run = run;
  }
}

class ToolRegistry {
  constructor() {
    this._byName = new Map();
  }

  register(tool) {
    if (!tool || !tool.name) throw new Error('register: tool with name required');
    if (this._byName.has(tool.name)) throw new Error(`register: tool ${tool.name} already registered`);
    this._byName.set(tool.name, tool);
    return this;
  }

  get(name) { return this._byName.get(name) || null; }

  list() { return [...this._byName.keys()]; }

  /**
   * Execute a tool if it is allowed for the task.
   *
   *   - default-deny: unregistered tool → ToolNotFoundError
   *   - per-task allowlist: the task's `allowedTools` must include the tool name
   *   - risk ceiling: the task's `maxRiskLevel` (optional) must be ≥ the tool's risk
   *   - timeout: enforced via Promise.race
   *   - output cap: enforced after the tool returns
   *   - audit: tool.call.start / tool.call.end / tool.call.error / tool.deny
   */
  async run(name, input, ctx = {}) {
    const tool = this._byName.get(name);
    if (!tool) {
      this._audit(ctx, 'tool.deny', { name, reason: 'not_registered' });
      throw new ToolNotFoundError(name);
    }
    const allowed = (ctx.allowedTools || []).includes(name);
    if (!allowed) {
      this._audit(ctx, 'tool.deny', { name, reason: 'not_in_allowed_tools' });
      throw new ToolDeniedError(name, 'not in task allowedTools');
    }
    const maxRisk = ctx.maxRiskLevel || 'destructive';
    if ((RISK_RANK[tool.riskLevel] || 0) > (RISK_RANK[maxRisk] || 4)) {
      this._audit(ctx, 'tool.deny', { name, reason: 'exceeds_max_risk' });
      throw new ToolDeniedError(name, `tool risk ${tool.riskLevel} > task max ${maxRisk}`);
    }
    this._audit(ctx, 'tool.call.start', { name, inputSummary: summariseInput(input) });
    const start = Date.now();
    let output;
    try {
      const result = await this._withTimeout(tool.run(input, ctx), tool.maxDurationMs, name);
      output = this._capOutput(result, tool.maxOutputBytes);
      this._audit(ctx, 'tool.call.end', { name, durationMs: Date.now() - start });
      return output;
    } catch (err) {
      this._audit(ctx, 'tool.call.error', { name, durationMs: Date.now() - start, error: String(err && err.message || err) });
      throw err;
    }
  }

  async _withTimeout(promise, ms, name) {
    let timer;
    return await Promise.race([
      Promise.resolve(promise).finally(() => clearTimeout(timer)),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new ToolError(`tool "${name}" timed out after ${ms}ms`, { code: 'TOOL_TIMEOUT', retryable: true })), ms);
      }),
    ]);
  }

  _capOutput(out, maxBytes) {
    const s = (() => {
      try { return JSON.stringify(out); } catch { return String(out); }
    })();
    if (Buffer.byteLength(s, 'utf-8') <= maxBytes) return out;
    // truncate: keep the prefix up to maxBytes
    return { __truncated: true, keptBytes: maxBytes, hint: 'output exceeded maxOutputBytes' };
  }

  _audit(ctx, kind, payload) {
    if (ctx.audit && typeof ctx.audit.append === 'function') {
      try { ctx.audit.append({ kind, ...payload }); } catch { /* never let audit failures break a tool call */ }
    }
  }
}

function summariseInput(input) {
  try {
    const s = JSON.stringify(input || {});
    if (s.length <= 200) return s;
    return s.slice(0, 200) + '…';
  } catch { return '<unserialisable>'; }
}

// ---- built-in safe tools ----

const safeEcho = new Tool({
  name: 'echo',
  purpose: 'Returns the input unchanged. Useful for tests and as a default fallback.',
  inputSchema: { type: 'object' },
  riskLevel: 'read',
  run: async (input) => input,
});

const safeHash = new Tool({
  name: 'hash.sha256',
  purpose: 'Computes a hex SHA-256 of the input string. No I/O.',
  inputSchema: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'] },
  riskLevel: 'read',
  run: async (input) => {
    const crypto = require('node:crypto');
    return crypto.createHash('sha256').update(String(input.value || '')).digest('hex');
  },
});

const safeRead = new Tool({
  name: 'fs.read',
  purpose: 'Reads a file under an allowlisted root. Path is restricted to the configured root.',
  inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
  requiredPermissions: ['fs.read'],
  riskLevel: 'read',
  run: async (input, ctx) => {
    const fs = require('node:fs');
    const path = require('node:path');
    if (!ctx.allowedRoots || ctx.allowedRoots.length === 0) {
      throw new ToolError('fs.read: allowedRoots is empty', { code: 'TOOL_DENIED' });
    }
    const abs = path.resolve(input.path);
    if (!ctx.allowedRoots.some((r) => abs === path.resolve(r) || abs.startsWith(path.resolve(r) + path.sep))) {
      throw new ToolError(`fs.read: ${abs} is outside allowed roots`, { code: 'TOOL_DENIED' });
    }
    return fs.readFileSync(abs, 'utf-8');
  },
});

const safeHttp = new Tool({
  name: 'http.get',
  purpose: 'Performs a read-only GET to a loopback URL. Use http.external for non-loopback targets.',
  inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
  requiredPermissions: ['http.get'],
  riskLevel: 'external',
  maxDurationMs: 8_000,
  run: async (input) => {
    const http = require('node:http');
    const { URL } = require('node:url');
    const u = new URL(input.url);
    if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost' && u.hostname !== '::1') {
      throw new ToolError('http.get: only loopback URLs are allowed by this tool', { code: 'TOOL_DENIED' });
    }
    return await new Promise((resolve, reject) => {
      const req = http.request({
        method: 'GET', hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search,
        timeout: 5_000,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf-8') }));
      });
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.end();
    });
  },
});

function buildDefaultRegistry() {
  const r = new ToolRegistry();
  r.register(safeEcho);
  r.register(safeHash);
  r.register(safeRead);
  r.register(safeHttp);
  return r;
}

module.exports = {
  Tool, ToolRegistry, ToolError, ToolDeniedError, ToolNotFoundError,
  RISK, RISK_RANK,
  safeEcho, safeHash, safeRead, safeHttp,
  buildDefaultRegistry,
};
