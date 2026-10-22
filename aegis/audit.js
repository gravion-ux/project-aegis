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
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class Audit {
  constructor(filePath, opts = {}) {
    this.filePath = filePath;
    this.fp = opts.fp || null;        // optional pre-opened fd
    this.key = opts.key || 'aegis-default-audit-key';
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

module.exports = { Audit };
