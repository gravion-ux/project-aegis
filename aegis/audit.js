'use strict';

/**
 * Append-only audit log.
 *
 * Records every task transition, every tool call, and every operator
 * action. Lines are written as one JSON object per line, with HMAC
 * chaining so that any in-place edit invalidates the chain.
 *
 * The audit log is *append-only by API*. The class exposes `append`
 * and `read` but no `update` / `delete` / `clear` methods.
 *
 * The chain key is a secret: anyone who knows it can forge a valid-looking
 * chain. The key therefore comes from the environment (`AEGIS_AUDIT_KEY`)
 * and is never a hard-coded constant in the source. When the environment
 * does not provide one, a random key is generated for this process only.
 * Such a log still detects corruption and tampering within the process
 * lifetime, but it cannot be verified against an external copy later —
 * `verify()` reports that explicitly instead of pretending the chain is
 * authenticated.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/**
 * Resolve the chain key.
 *
 * @returns {{ key: string, persistent: boolean }}
 */
function resolveKey() {
  const fromEnv = process.env.AEGIS_AUDIT_KEY;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    return { key: fromEnv, persistent: true };
  }
  // A per-process random key. It is not published, so it cannot be used to
  // forge a chain — but it also cannot be re-derived later, so the chain is
  // only verifiable within this process.
  return { key: crypto.randomBytes(32).toString('hex'), persistent: false };
}

class Audit {
  constructor(filePath, opts = {}) {
    this.filePath = filePath;
    this.fp = opts.fp || null;        // optional pre-opened fd
    if (opts.key) {
      this.key = opts.key;
      // An explicitly supplied key is stable by definition.
      this.keyIsPersistent = true;
    } else {
      const resolved = resolveKey();
      this.key = resolved.key;
      this.keyIsPersistent = resolved.persistent;
    }
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    if (!this.fp) {
      this.fp = fs.openSync(filePath, 'a');
    }
  }

  append(event) {
    if (!event || typeof event !== 'object') {
      throw new Error('audit event must be an object');
    }
    const last = this._lastHash();
    const record = {
      ts: new Date().toISOString(),
      prev: last,
      event,
    };
    const payload = JSON.stringify(record);
    const hash = crypto.createHmac('sha256', this.key).update(payload).digest('hex');
    const line = JSON.stringify({ ...record, hash }) + '\n';
    fs.writeSync(this.fp, line);
    return record;
  }

  read() {
    if (!fs.existsSync(this.filePath)) return [];
    const raw = fs.readFileSync(this.filePath, 'utf-8');
    const out = [];
    for (const line of raw.split('\n')) {
      if (!line) continue;
      try { out.push(JSON.parse(line)); } catch { /* skip malformed */ }
    }
    return out;
  }

  /**
   * Verify the hash chain.
   *
   * Recomputes every event's hash and checks that each event's `prev`
   * matches the hash of the event before it. A tampered, reordered or
   * removed event is reported.
   *
   * @returns {{ ok: boolean, checked: number, errors: string[], authenticated: boolean }}
   */
  verify() {
    const records = this.read();
    const errors = [];
    let prev = null;
    records.forEach((rec, i) => {
      const { hash, ...rest } = rec;
      const expected = crypto.createHmac('sha256', this.key)
        .update(JSON.stringify(rest))
        .digest('hex');
      if (hash !== expected) {
        errors.push(`record ${i}: hash mismatch`);
      }
      if (rec.prev !== prev) {
        errors.push(`record ${i}: prev does not match the preceding record`);
      }
      prev = hash;
    });
    return {
      ok: errors.length === 0,
      checked: records.length,
      errors,
      // The chain is only *authenticated* when the key is stable across
      // restarts. With a per-process key the chain still detects corruption
      // inside this process, but it cannot prove authorship later.
      authenticated: this.keyIsPersistent,
    };
  }

  _lastHash() {
    if (!fs.existsSync(this.filePath)) return null;
    const raw = fs.readFileSync(this.filePath, 'utf-8');
    const lines = raw.split('\n').filter((l) => l.length > 0);
    if (lines.length === 0) return null;
    try {
      const last = JSON.parse(lines[lines.length - 1]);
      return last.hash || null;
    } catch {
      return null;
    }
  }

  close() {
    if (this.fp != null) {
      try { fs.closeSync(this.fp); } catch {}
      this.fp = null;
    }
  }
}

module.exports = { Audit, resolveKey };
