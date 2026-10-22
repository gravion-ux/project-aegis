'use strict';

/**
 * Provider registry and router.
 *
 * The registry is the only place that knows about concrete provider
 * implementations. The router takes a model name and returns the
 * provider that owns it. Unknown models are rejected.
 *
 * The router also enforces the "no silent fallback to paid" rule:
 * a paid provider is only selected if the config has explicitly
 * enabled it (allowPaid: true). When a model name looks paid and
 * that flag is off, the router **throws** a ProviderError rather than
 * quietly returning the offline provider — a silent substitution
 * would produce output that looks like a real model answer but is
 * not one.
 */

const { OfflineProvider } = require('./offline');
const { HttpProvider } = require('./http');
const { ProviderError } = require('./base');

class ProviderRegistry {
  constructor() {
    this._byName = new Map();
  }

  register(name, provider) {
    if (!name || !provider) throw new Error('register: name and provider required');
    this._byName.set(name, provider);
    return this;
  }

  get(name) {
    return this._byName.get(name) || null;
  }

  list() {
    return [...this._byName.keys()];
  }
}

class ProviderRouter {
  constructor({ registry, allowPaid = false, env = process.env } = {}) {
    this.registry = registry || new ProviderRegistry();
    this.allowPaid = !!allowPaid;
    this.env = env;
  }

  /**
   * Resolve a model name to a provider.
   * Falls back to `offline` if the named provider is paid and not allowed.
   */
  resolve(modelName) {
    const m = modelName || 'offline';
    if (m === 'offline') {
      if (!this.registry.get('offline')) this.registry.register('offline', new OfflineProvider());
      return this.registry.get('offline');
    }
    // HTTP providers: read URL and optional auth from env
    if (m.startsWith('http:') || m.startsWith('https:')) {
      return this._fromEnv(m);
    }
    // Heuristic: any model name containing '/' or 'gpt'/'claude' is treated as a paid provider
    const looksPaid = /gpt-|claude-|gemini-|command-/.test(m);
    if (looksPaid && !this.allowPaid) {
      throw new ProviderError(`paid provider for model "${m}" is not enabled (set allowPaid:true in config)`);
    }
    // Default: still try env-backed http
    return this._fromEnv(m);
  }

  _fromEnv(m) {
    const baseUrl = this.env.AEGIS_LLM_URL;
    if (!baseUrl) {
      throw new ProviderError(
        `AEGIS_LLM_URL is not set; cannot route model "${m}". Set the env var to a local model server URL.`,
      );
    }
    const authEnv = this.env.AEGIS_LLM_AUTH_HEADER;
    const provider = new HttpProvider({
      baseUrl,
      model: m,
      authHeader: authEnv || null,
    });
    return provider;
  }
}

module.exports = { ProviderRegistry, ProviderRouter };
