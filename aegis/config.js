'use strict';

/**
 * Typed configuration loader (Phase 2).
 *
 * Configuration is loaded from `aegis.config.json` in the workspace
 * root, and may be overridden by environment variables. There are NO
 * secrets in the config file. If the operator needs an API key for a
 * real provider, they set `AEGIS_LLM_AUTH_HEADER` in the environment.
 *
 * Missing config is not an error: sensible defaults are used.
 */

const fs = require('node:fs');
const path = require('node:path');

const DEFAULTS = Object.freeze({
  provider: {
    default: 'offline',
    allowPaid: false,
    timeoutMs: 30_000,
    maxRetries: 1,
  },
  budget: {
    maxInputChars: null,
    maxOutputChars: 200_000,
    maxTokens: null,
    maxCost: null,
    pricing: null,
  },
  runtime: {
    maxIterations: 3,
    maxWallMs: 60_000,
    maxDelegationDepth: 2,
    maxRetries: 2,
  },
  memory: {
    retentionMs: null,
    maxRecordsPerProject: 5_000,
  },
});

function deepMerge(base, override) {
  if (!override || typeof override !== 'object') return base;
  const out = Array.isArray(base) ? base.slice() : { ...base };
  for (const [k, v] of Object.entries(override)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && out[k] && typeof out[k] === 'object' && !Array.isArray(out[k])) {
      out[k] = deepMerge(out[k], v);
    } else if (v !== undefined) {
      out[k] = v;
    }
  }
  return out;
}

function loadConfig(root, env = process.env) {
  let fileConfig = {};
  const file = path.join(root, 'aegis.config.json');
  if (fs.existsSync(file)) {
    try {
      fileConfig = JSON.parse(fs.readFileSync(file, 'utf-8')) || {};
    } catch (err) {
      throw new Error(`aegis.config.json is not valid JSON: ${err.message}`);
    }
  }
  let cfg = deepMerge(DEFAULTS, fileConfig);

  // Environment overrides (no secrets are read from the config file)
  if (env.AEGIS_ALLOW_PAID === 'true') cfg.provider.allowPaid = true;
  if (env.AEGIS_DEFAULT_MODEL) cfg.provider.default = env.AEGIS_DEFAULT_MODEL;
  if (env.AEGIS_MAX_OUTPUT_CHARS) {
    const n = Number.parseInt(env.AEGIS_MAX_OUTPUT_CHARS, 10);
    if (Number.isFinite(n)) cfg.budget.maxOutputChars = n;
  }

  // Never allow a secret to appear in the config object we return.
  return stripSecrets(cfg);
}

function stripSecrets(cfg) {
  const banned = /(token|secret|password|api[_-]?key|authorization)/i;
  function walk(node) {
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (banned.test(k)) continue;
        out[k] = walk(v);
      }
      return out;
    }
    return node;
  }
  return walk(cfg);
}

function validateConfig(cfg) {
  const problems = [];
  if (!cfg.provider || typeof cfg.provider.default !== 'string') {
    problems.push('provider.default must be a string');
  }
  if (cfg.budget && cfg.budget.maxCost != null && typeof cfg.budget.maxCost !== 'number') {
    problems.push('budget.maxCost must be a number or null');
  }
  if (cfg.budget && cfg.budget.pricing != null) {
    const p = cfg.budget.pricing;
    if (typeof p.inputPer1k !== 'number' || typeof p.outputPer1k !== 'number') {
      problems.push('budget.pricing must define numeric inputPer1k and outputPer1k');
    }
  }
  return problems;
}

module.exports = { loadConfig, validateConfig, stripSecrets, DEFAULTS };