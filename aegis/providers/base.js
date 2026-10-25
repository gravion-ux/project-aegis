'use strict';

/**
 * Provider interface.
 *
 * Every provider must implement:
 *   - name:    string
 *   - capabilities(): { chat, embeddings, toolUse, vision, ... }
 *   - complete(request): Promise<ProviderResponse>
 *   - usage(): ProviderUsage | null
 *   - pricing(): { inputPer1k, outputPer1k, currency } | null
 *
 * ProviderResponse is { text, model, finishReason, raw, usage? }.
 * ProviderUsage is { input, output, total } in *characters* unless the
 * provider supplies real token counts (the HTTP provider does).
 */

class ProviderError extends Error {
  constructor(message, { retryable = false, cause = null, code = 'PROVIDER_ERROR' } = {}) {
    super(message);
    this.name = 'ProviderError';
    this.retryable = retryable;
    this.cause = cause;
    // A machine-readable code, so a caller can distinguish an abort from a
    // timeout from a transport failure without matching on the message.
    this.code = code;
  }
}

function assertRequest(request) {
  if (!request || typeof request !== 'object') throw new ProviderError('request must be an object');
  if (!Array.isArray(request.messages) || request.messages.length === 0) {
    throw new ProviderError('request.messages must be a non-empty array');
  }
  for (const m of request.messages) {
    if (!m || typeof m !== 'object') throw new ProviderError('message must be an object');
    if (typeof m.role !== 'string') throw new ProviderError('message.role must be a string');
    if (typeof m.content !== 'string') throw new ProviderError('message.content must be a string');
  }
}

module.exports = { ProviderError, assertRequest };
