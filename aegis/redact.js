'use strict';

/**
 * Redaction helpers.
 *
 * The logger redacts well-known secret patterns before writing.
 * Patterns are intentionally conservative: false positives are
 * acceptable; false negatives are not.
 */

const SECRET_RE = /(token|api[_-]?key|secret|password)\s*[:=]\s*([^\s"',]+)/gi;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._\-]+/g;

function redactString(input) {
  if (typeof input !== 'string') return input;
  // Bearer token first (so the line "Authorization: Bearer xyz" is fully
  // covered by the bearer rule alone — Authorization is not a secret key
  // by itself, the token is).
  let s = input.replace(BEARER_RE, 'Bearer [REDACTED]');
  s = s.replace(SECRET_RE, (_m, key) => `${key}: [REDACTED]`);
  return s;
}

function redact(value) {
  if (value == null) return value;
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map(redact);
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redact(v);
    return out;
  }
  return value;
}

module.exports = { redact, redactString };
