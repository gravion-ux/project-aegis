'use strict';

/**
 * Deterministic offline provider.
 *
 * Produces a stable response for a given prompt. NEVER pretends to be
 * a real LLM. The "model" is always `offline` and the response is
 * the input echoed with a small deterministic transform so that
 * downstream code that depends on non-empty output still works.
 *
 * Usage is measured in *characters*, not tokens, because we have no
 * tokenizer.
 */

const { assertRequest, ProviderError } = require('./base');

class OfflineProvider {
  constructor(opts = {}) {
    this.name = 'offline';
    this._last = null;
    this._totalInput = 0;
    this._totalOutput = 0;
  }

  capabilities() {
    return { chat: true, embeddings: false, toolUse: false, vision: false, streaming: false };
  }

  async complete(request) {
    assertRequest(request);
    if (!request.messages || request.messages.length === 0) {
      throw new ProviderError('offline: empty messages');
    }
    const lastUser = [...request.messages].reverse().find((m) => m.role === 'user');
    if (!lastUser) {
      throw new ProviderError('offline: no user message in request');
    }
    const text = deterministicTransform(lastUser.content);
    this._last = text;
    this._totalInput += request.messages.reduce((n, m) => n + m.content.length, 0);
    this._totalOutput += text.length;
    return {
      text,
      model: 'offline',
      finishReason: 'stop',
      usage: { input: lastUser.content.length, output: text.length, total: lastUser.content.length + text.length },
    };
  }

  usage() {
    return {
      input: this._totalInput,
      output: this._totalOutput,
      total: this._totalInput + this._totalOutput,
      unit: 'chars',
    };
  }

  pricing() {
    return { inputPer1k: 0, outputPer1k: 0, currency: 'USD', free: true };
  }
}

function deterministicTransform(input) {
  const text = String(input);
  // Stable hash → hex prefix → uppercase, prefixed by a fixed label.
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) {
    h = ((h << 5) + h + text.charCodeAt(i)) | 0;
  }
  const hex = (h >>> 0).toString(16).padStart(8, '0');
  return `[offline:${hex}] ${text}`;
}

module.exports = { OfflineProvider, deterministicTransform };
