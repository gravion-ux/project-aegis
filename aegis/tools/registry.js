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

// Hard ceiling on what a single tool call may pull into memory. The
// registry-level `maxOutputBytes` truncates *after* a tool returns, which
// is too late for a tool that reads a file or a response body into memory
// first. These limits are enforced by the tools themselves.
const MAX_READ_BYTES = 1024 * 1024;   // 1 MiB
const MAX_HTTP_BYTES = 1024 * 1024;   // 1 MiB

/**
 * Link a caller's AbortSignal into a controller we own.
 *
 * The controller lets a timeout abort the tool, instead of merely
 * abandoning it: `Promise.race` rejects the caller but the tool body keeps
 * running and can keep producing side effects.
 *
 * @returns {function} a cleanup function that removes the listener
 */
function linkAbort(signal, controller) {
  if (!signal || typeof signal.addEventListener !== 'function') return () => {};
  if (signal.aborted) {
    controller.abort(signal.reason);
    return () => {};
  }
  const onAbort = () => controller.abort(signal.reason);
  signal.addEventListener('abort', onAbort, { once: true });
  return () => signal.removeEventListener('abort', onAbort);
}

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
   *   - cancellation: an already-aborted run never starts the tool
   *   - timeout: enforced via Promise.race, and the tool is aborted too
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
    // Cooperative cancellation. A cancelled run must not start new work.
    if (ctx.signal && ctx.signal.aborted) {
      this._audit(ctx, 'tool.deny', { name, reason: 'aborted' });
      throw new ToolError(`tool "${name}" not started: the run was cancelled`, { code: 'ABORTED' });
    }

    this._audit(ctx, 'tool.call.start', { name, inputSummary: summariseInput(input) });
    const start = Date.now();

    // A controller we own, so a timeout can abort the tool rather than
    // merely abandoning it. The caller's signal is linked into it, so a
    // cancellation also reaches the tool.
    const controller = new AbortController();
    const unlink = linkAbort(ctx.signal, controller);
    const toolCtx = { ...ctx, signal: controller.signal };

    let output;
    try {
      const result = await this._withTimeout(tool.run(input, toolCtx), tool.maxDurationMs, name, controller);
      output = this._capOutput(result, tool.maxOutputBytes);
      this._audit(ctx, 'tool.call.end', { name, durationMs: Date.now() - start });
      return output;
    } catch (err) {
      this._audit(ctx, 'tool.call.error', { name, durationMs: Date.now() - start, error: String(err && err.message || err) });
      throw err;
    } finally {
      unlink();
    }
  }

  async _withTimeout(promise, ms, name, controller) {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        const err = new ToolError(`tool "${name}" timed out after ${ms}ms`, { code: 'TOOL_TIMEOUT', retryable: true });
        // Abort the tool so it can stop. Without this the tool body keeps
        // running after the caller has already been told it timed out.
        try { if (controller) controller.abort(err); } catch { /* ignore */ }
        reject(err);
      }, ms);
    });
    try {
      return await Promise.race([Promise.resolve(promise).finally(() => clearTimeout(timer)), timeout]);
    } finally {
      clearTimeout(timer);
    }
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
  maxOutputBytes: MAX_READ_BYTES,
  run: async (input, ctx) => {
    const fs = require('node:fs');
    const path = require('node:path');
    if (!ctx.allowedRoots || ctx.allowedRoots.length === 0) {
      throw new ToolError('fs.read: allowedRoots is empty', { code: 'TOOL_DENIED' });
    }
    if (ctx.signal && ctx.signal.aborted) {
      throw new ToolError('fs.read: cancelled', { code: 'ABORTED' });
    }
    const abs = path.resolve(input.path);
    if (!ctx.allowedRoots.some((r) => abs === path.resolve(r) || abs.startsWith(path.resolve(r) + path.sep))) {
      throw new ToolError(`fs.read: ${abs} is outside allowed roots`, { code: 'TOOL_DENIED' });
    }

    let stat;
    try { stat = fs.statSync(abs); }
    catch { throw new ToolError(`fs.read: cannot stat ${abs}`, { code: 'TOOL_ERROR' }); }
    if (!stat.isFile()) {
      throw new ToolError('fs.read: not a regular file', { code: 'TOOL_DENIED' });
    }
    // Refuse an oversized file *before* reading it. The registry-level
    // output cap truncates after the fact, which still means the whole
    // file was pulled into memory first.
    if (stat.size > MAX_READ_BYTES) {
      throw new ToolError(
        `fs.read: file is ${stat.size} bytes, over the ${MAX_READ_BYTES} byte limit`,
        { code: 'TOOL_OUTPUT_TOO_LARGE' },
      );
    }

    // Re-check containment against the *resolved* path, so a symlink
    // inside an allowed root cannot point outside it.
    const realAbs = safeRealpath(fs, abs);
    const stillInside = ctx.allowedRoots.some((r) => {
      const realRoot = safeRealpath(fs, path.resolve(r));
      if (!realRoot) return false;
      return realAbs === realRoot || realAbs.startsWith(realRoot + path.sep);
    });
    if (!stillInside) {
      throw new ToolError(`fs.read: ${abs} resolves outside allowed roots`, { code: 'TOOL_DENIED' });
    }

    if (ctx.signal && ctx.signal.aborted) {
      throw new ToolError('fs.read: cancelled', { code: 'ABORTED' });
    }
    return fs.readFileSync(realAbs, 'utf-8');
  },
});

/**
 * realpath that tolerates a missing path — the caller has already
 * established that the file exists, but a race could still remove it.
 */
function safeRealpath(fs, p) {
  try { return fs.realpathSync(p); } catch { return null; }
}

const safeHttp = new Tool({
  name: 'http.get',
  purpose: 'Performs a read-only GET to a loopback URL. Use http.external for non-loopback targets.',
  inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
  requiredPermissions: ['http.get'],
  riskLevel: 'external',
  maxDurationMs: 8_000,
  maxOutputBytes: MAX_HTTP_BYTES,
  run: async (input, ctx = {}) => {
    const http = require('node:http');
    const { URL } = require('node:url');
    const u = new URL(input.url);
    // The URL parser normalises the host, so `http://2130706433/` and
    // `http://127.1/` both arrive here as 127.0.0.1. An IPv6 loopback
    // arrives as "[::1]", so both spellings are accepted.
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
      throw new ToolError('http.get: only loopback URLs are allowed by this tool', { code: 'TOOL_DENIED' });
    }
    if (ctx.signal && ctx.signal.aborted) {
      throw new ToolError('http.get: cancelled', { code: 'ABORTED' });
    }
    return await new Promise((resolve, reject) => {
      let settled = false;
      const done = (fn, v) => { if (settled) return; settled = true; fn(v); };
      const req = http.request({
        method: 'GET', hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search,
        timeout: 5_000,
      }, (res) => {
        const chunks = [];
        let total = 0;
        res.on('data', (c) => {
          total += c.length;
          // Stop pulling the body in once it is over the limit. Buffering
          // an unbounded response is a denial-of-service on the process.
          if (total > MAX_HTTP_BYTES) {
            req.destroy();
            done(reject, new ToolError(
              `http.get: response exceeded ${MAX_HTTP_BYTES} bytes`,
              { code: 'TOOL_OUTPUT_TOO_LARGE' },
            ));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => done(resolve, { status: res.statusCode, body: Buffer.concat(chunks).toString('utf-8') }));
      });
      req.on('error', (e) => done(reject, e));
      req.on('timeout', () => req.destroy(new Error('timeout')));
      if (ctx.signal) {
        const onAbort = () => { req.destroy(); done(reject, new ToolError('http.get: cancelled', { code: 'ABORTED' })); };
        if (ctx.signal.aborted) { onAbort(); return; }
        ctx.signal.addEventListener('abort', onAbort, { once: true });
      }
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
