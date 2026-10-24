'use strict';

/**
 * File-backed task storage.
 *
 * One JSON file per task in `state/<taskId>.json`. A small in-memory
 * index is kept in `state/_index.json` and rebuilt on load. Writes are
 * atomic via `writeFile` to a temp file + rename.
 *
 * The store is single-process. If you need multi-process safety, add
 * `proper-lockfile` later — the interface is already narrow.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isSafeIdentifier, recordPath } = require('./paths');

class Storage {
  constructor(rootDir) {
    this.root = rootDir;
    fs.mkdirSync(this.root, { recursive: true });
    this.indexPath = path.join(this.root, '_index.json');
    this._index = this._loadIndex();
  }

  _loadIndex() {
    if (!fs.existsSync(this.indexPath)) {
      return { tasks: {}, version: 1, updatedAt: new Date().toISOString() };
    }
    try {
      const j = JSON.parse(fs.readFileSync(this.indexPath, 'utf-8'));
      if (!j || typeof j !== 'object') return { tasks: {}, version: 1, updatedAt: new Date().toISOString() };
      j.tasks = j.tasks || {};
      return j;
    } catch {
      return { tasks: {}, version: 1, updatedAt: new Date().toISOString() };
    }
  }

  _saveIndex() {
    this._index.updatedAt = new Date().toISOString();
    this._writeAtomic(this.indexPath, JSON.stringify(this._index, null, 2));
  }

  _writeAtomic(target, body) {
    const tmp = `${target}.tmp-${crypto.randomBytes(6).toString('hex')}`;
    fs.writeFileSync(tmp, body);
    fs.renameSync(tmp, target);
  }

  list() {
    return Object.values(this._index.tasks);
  }

  get(taskId) {
    // An id that could escape the state directory is simply "not found";
    // it is never used to build a path.
    if (!isSafeIdentifier(taskId)) return null;
    const meta = Object.prototype.hasOwnProperty.call(this._index.tasks, taskId)
      ? this._index.tasks[taskId]
      : null;
    if (!meta) return null;
    const file = recordPath(this.root, taskId, '.json', 'task id');
    if (!fs.existsSync(file)) return null;
    try {
      const full = JSON.parse(fs.readFileSync(file, 'utf-8'));
      return full;
    } catch {
      return null;
    }
  }

  put(task) {
    if (!task || !task.id) throw new Error('storage.put: task.id is required');
    // A write must never land outside the state directory, so an unsafe id
    // is a hard error rather than a silent no-op.
    const file = recordPath(this.root, task.id, '.json', 'task id');
    this._writeAtomic(file, JSON.stringify(task, null, 2));
    this._index.tasks[task.id] = {
      id: task.id,
      state: task.state,
      role: task.role,
      title: task.title,
      updatedAt: task.updatedAt || new Date().toISOString(),
    };
    this._saveIndex();
    return task;
  }

  remove(taskId) {
    if (!isSafeIdentifier(taskId)) return;
    const file = recordPath(this.root, taskId, '.json', 'task id');
    if (fs.existsSync(file)) fs.unlinkSync(file);
    delete this._index.tasks[taskId];
    this._saveIndex();
  }
}

module.exports = { Storage };
