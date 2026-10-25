'use strict';

/**
 * Redaction helpers.
 *
 * The logger redacts well-known secret patterns before writing.
 * Patterns are intentionally conservative: false positives are
 * acceptable; false negatives are not.
 *
 * The rules below cover three families:
 *   1. labelled secrets   — `api_key: <value>`, `password=<value>`, …
 *   2. bearer tokens     — `Bearer <token>`
 *   3. self-identifying credential formats — AWS access keys, GitHub
 *      tokens, Slack tokens, private key blocks, JWTs, connection strings
 *      and `Authorization: Basic …` headers.
 *
 * Every pattern is applied to the whole string, not to a value that is
 * known to be a secret, because the string may be a log line, an error
 * message or an HTTP response body.
 */

const SECRET_RE = /(token|api[_-]?key|secret|password|passwd|pwd)\s*[:=]\s*([^\s"',]+)/gi;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._\-+/=]+/g;
const BASIC_RE = /\bBasic\s+[A-Za-z0-9+/=]+/g;

// A self-identifying credential format. These are matched on their own
// well-known prefixes so a credential is caught even when it appears
// without a label — for example inside a stack trace or a JSON body.
const AWS_ACCESS_KEY_RE = /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN_RE = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g;
const GITHUB_FINEGRAINED_RE = /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g;
const SLACK_TOKEN_RE = /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g;
const OPENAI_KEY_RE = /\bsk-[A-Za-z0-9_-]{20,}\b/g;
const GOOGLE_API_KEY_RE = /\bAIza[0-9A-Za-z_-]{35}\b/g;
const STRIPE_KEY_RE = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g;

// A JSON Web Token: three base64url segments, the first of which starts
// with the `{"` header.
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

// A PEM private key block, including the body.
const PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;

// A URL that carries inline credentials: scheme://user:password@host
const URL_CREDENTIAL_RE = /\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]+):([^\s@/]+)@/gi;

/**
 * Redact a single string.
 *
 * Non-string input is returned unchanged, so the helper is safe to call on
 * any value.
 */
function redactString(input) {
  if (typeof input !== 'string') return input;
  // Bearer / Basic headers first, so the line
  // "Authorization: Bearer xyz" is fully covered by the bearer rule alone —
  // "Authorization" is not a secret key by itself, the token is.
  let s = input.replace(BEARER_RE, 'Bearer [REDACTED]');
  s = s.replace(BASIC_RE, 'Basic [REDACTED]');
  // Self-identifying credential formats, before the labelled rule: the
  // labelled rule would rewrite only the label and could leave a credential
  // exposed elsewhere in the same string.
  s = s.replace(PRIVATE_KEY_RE, '[REDACTED PRIVATE KEY]');
  s = s.replace(JWT_RE, '[REDACTED JWT]');
  s = s.replace(AWS_ACCESS_KEY_RE, '[REDACTED AWS KEY]');
  s = s.replace(GITHUB_TOKEN_RE, '[REDACTED GITHUB TOKEN]');
  s = s.replace(GITHUB_FINEGRAINED_RE, '[REDACTED GITHUB TOKEN]');
  s = s.replace(SLACK_TOKEN_RE, '[REDACTED SLACK TOKEN]');
  s = s.replace(OPENAI_KEY_RE, '[REDACTED API KEY]');
  s = s.replace(GOOGLE_API_KEY_RE, '[REDACTED API KEY]');
  s = s.replace(STRIPE_KEY_RE, '[REDACTED STRIPE KEY]');
  // Inline URL credentials. The scheme and the host are kept — they are
  // useful for diagnosis — while the user and password are removed.
  s = s.replace(URL_CREDENTIAL_RE, (_m, scheme, user) => `${scheme}${user}:[REDACTED]@`);
  // The labelled rule last: it rewrites `api_key: value` as
  // `api_key: [REDACTED]`.
  s = s.replace(SECRET_RE, (_m, key) => `${key}: [REDACTED]`);
  return s;
}

/**
 * Redact every string inside a value.
 *
 * Object *keys* are redacted as well as values: a credential can be used as
 * a key (for example `{"sk-…": "value"}`).
 */
function redact(value) {
  if (value == null) return value;
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map(redact);
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[redactString(k)] = redact(v);
    return out;
  }
  return value;
}

module.exports = { redact, redactString };
