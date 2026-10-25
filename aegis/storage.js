'use strict';

/**
 * File-backed task storage.
 *
 * One JSON file per task in `state/<taskId>.json`. A small task index is
 * kept in `state/_index.json`. Writes are atomic via `writeFile` to a temp
 * file + rename.
 *
 * The index is shared state: every read and every write goes back to the
 * file, so two writers over the same directory no longer clobber each
 * other's task entries. Truly simultaneous writes can still race — closing
 * that window needs a lock file, which is a later phase. The interface here
 * is already narrow enough to add one.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isSafeIdentifier, recordPath } = require('./paths');

/**
 * An empty task map with a null prototype.
 *
 * `Object.create(null)` has no inherited `__proto__` setter, so a task whose
 * id is `__proto__` becomes an ordinary own entry instead of silently
 * replacing the map's prototype.
 */
function emptyIndex() {
  return Object.create(null);
}

/**
 * Normalise a task map loaded from disk into a null-prototype object.
 *
 * `JSON.parse` creates own properties for `__proto__` correctly, but the
 * resulting object still inherits from `Object.prototype`, so a later
 * `put()` of a task called `__proto__` would hit the inherited setter.
 */
function toTaskMap(raw) {
  const map = emptyIndex();
  if (!raw || typeof raw !== 'object') return map;
  for (const [k, v] of Object.entries(raw)) map[k] = v;
  return map;
}

class Storage {
  constructor(rootDir) {
    this.root = rootDir;
    fs.mkdirSync(this.root, { recursive: true });
    this.indexPath = path.join(this.root, '_index.json');
    this._index = this._loadIndex();
  }

  /**
   * Read the index from disk.
   *
   * The index is a *shared* file. Two AEGIS processes — or two `Storage`
   * instances in one process — can point at the same state directory, so an
   * in-memory snapshot is never authoritative. A write that reused a stale
   * snapshot would silently drop every task the other writer had indexed:
   * the task file would still be on disk, but the index would no longer
   * mention it and `list()` / `get()` would never find it again.
   */
  _loadIndex() {
    if (!fs.existsSync(this.indexPath)) {
      return { tasks: emptyIndex(), version: 1, updatedAt: new Date().toISOString() };
    }
    try {
      const j = JSON.parse(fs.readFileSync(this.indexPath, 'utf-8'));
      if (!j || typeof j !== 'object') return { tasks: emptyIndex(), version: 1, updatedAt: new Date().toISOString() };
      // The task map is rebuilt with a null prototype. A plain `{}` inherits
      // `__proto__` from Object.prototype, so assigning the task id
      // `__proto__` would replace the map's prototype instead of adding an
      // entry — the task would be written to disk but be invisible to
      // `list()` and `get()`.
      j.tasks = toTaskMap(j.tasks);
      return j;
    } catch {
      return { tasks: emptyIndex(), version: 1, updatedAt: new Date().toISOString() };
    }
  }

  /**
   * Apply one change to the index and write it back.
   *
   * The change is merged into a *freshly read* copy of the on-disk index, so
   * a concurrent writer's tasks are preserved. Only the key being changed is
   * touched, so a stale instance cannot resurrect a task another writer
   * removed.
   *
   * @param {string} taskId  the key to change
   * @param {object|null} entry  the new entry, or null to remove the key
   */
  _writeIndexEntry(taskId, entry) {
    const index = this._loadIndex();
    if (entry === null) delete index.tasks[taskId];
    else index.tasks[taskId] = entry;
    index.updatedAt = new Date().toISOString();
    this._writeAtomic(this.indexPath, JSON.stringify(index, null, 2));
    this._index = index;
  }

  _writeAtomic(target, body) {
    const tmp = `${target}.tmp-${crypto.randomBytes(6).toString('hex')}`;
    fs.writeFileSync(tmp, body);
    fs.renameSync(tmp, target);
  }

  list() {
    // Refreshed from disk, so a long-lived instance does not serve a listing
    // that another writer has already moved past.
    this._index = this._loadIndex();
    return Object.values(this._index.tasks);
  }

  get(taskId) {
    // An id that could escape the state directory is simply "not found";
    // it is never used to build a path.
    if (!isSafeIdentifier(taskId)) return null;
    this._index = this._loadIndex();
    const meta = Object.prototype.hasOwnProperty.call(this._index.tasks, taskId)
      ? this._index.tasks[taskId]
      : null;
    if (!meta) return null;
    const file = recordPath(this.root, taskId, '.json', 'task id');
    const full = this._readTaskFile(file);
    if (!full) return null;
    // The id recorded inside the file must match the id that was asked for.
    // On a case-insensitive filesystem `Alpha.json` and `alpha.json` are the
    // same file, so without this check one task could be served under
    // another task's id.
    if (full.id != null && full.id !== taskId) return null;
    return full;
  }

  /**
   * Read a task file, tolerating a missing or corrupt file.
   * @returns {object|null}
   */
  _readTaskFile(file) {
    if (!fs.existsSync(file)) return null;
    try {
      return JSON.parse(fs.readFileSync(file, 'utf-8'));
    } catch {
      return null;
    }
  }

  put(task) {
    if (!task || !task.id) throw new Error('storage.put: task.id is required');
    // A write must never land outside the state directory, so an unsafe id
    // is a hard error rather than a silent no-op.
    const file = recordPath(this.root, task.id, '.json', 'task id');
    // The index has its own filename inside the same directory. A task id
    // that resolves to it would overwrite the index on the next save, so
    // the collision is refused.
    if (path.resolve(file) === path.resolve(this.indexPath)) {
      const err = new Error(
        `storage.put: task id ${JSON.stringify(task.id)} resolves to the task index file`,
      );
      err.code = 'INVALID_ID';
      throw err;
    }
    // Two different ids can resolve to the same file on a case-insensitive
    // filesystem (`Alpha` and `alpha`). Writing would silently destroy the
    // other task's record, so the conflict is refused instead — the same
    // behaviour on every platform.
    const existing = this._readTaskFile(file);
    if (existing && existing.id != null && existing.id !== task.id) {
      const err = new Error(
        `storage.put: task id ${JSON.stringify(task.id)} resolves to the same file as existing task ` +
        `${JSON.stringify(existing.id)}; refusing to overwrite it`,
      );
      err.code = 'TASK_ID_CONFLICT';
      throw err;
    }
    this._writeAtomic(file, JSON.stringify(task, null, 2));
    this._writeIndexEntry(task.id, {
      id: task.id,
      state: task.state,
      role: task.role,
      title: task.title,
      updatedAt: task.updatedAt || new Date().toISOString(),
    });
    return task;
  }

  remove(taskId) {
    if (!isSafeIdentifier(taskId)) return;
    const file = recordPath(this.root, taskId, '.json', 'task id');
    if (fs.existsSync(file)) fs.unlinkSync(file);
    this._writeIndexEntry(taskId, null);
  }
}

module.exports = { Storage };
