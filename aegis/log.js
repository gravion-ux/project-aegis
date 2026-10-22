'use strict';

/**
 * Structured logger.
 *
 * Emits one JSON object per line to a stream (default: stdout).
 * Every record includes: ts, level, msg, and arbitrary structured fields.
 * Strings are redacted before writing.
 */

const fs = require('node:fs');
const path = require('node:path');
const { redact } = require('./redact');

const LEVELS = ['debug', 'info', 'warn', 'error'];

class Logger {
  constructor(opts = {}) {
    this.stream = opts.stream || process.stdout;
    this.minLevel = opts.minLevel || 'info';
    this.minLevelIndex = LEVELS.indexOf(this.minLevel);
    this.component = opts.component || 'aegis';
    this.fields = opts.fields || {};
  }

  child(extra) {
    return new Logger({
      stream: this.stream,
      minLevel: this.minLevel,
      component: this.component,
      fields: { ...this.fields, ...(extra || {}) },
    });
  }

  _emit(level, msg, fields) {
    if (LEVELS.indexOf(level) < this.minLevelIndex) return;
    const record = redact({
      ts: new Date().toISOString(),
      level,
      component: this.component,
      msg: typeof msg === 'string' ? msg : String(msg),
      ...this.fields,
      ...(fields || {}),
    });
    this.stream.write(JSON.stringify(record) + '\n');
  }

  debug(msg, fields) { this._emit('debug', msg, fields); }
  info(msg, fields)  { this._emit('info',  msg, fields); }
  warn(msg, fields)  { this._emit('warn',  msg, fields); }
  error(msg, fields) { this._emit('error', msg, fields); }
}

function fileLogger(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const stream = fs.createWriteStream(filePath, { flags: 'a' });
  return new Logger({ stream });
}

module.exports = { Logger, fileLogger, LEVELS };
