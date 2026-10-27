'use strict';

/**
 * Project-scoped memory store (Phase 2).
 *
 * The Phase 1 API (`list`, `add`, `search`) is preserved. Phase 2
 * adds:
 *   - schema validation and quarantine for malformed records
 *   - task-level memory (records scoped to a task, not just a project)
 *   - update / delete / get
 *   - dedup on identical and near-identical key/value
 *   - retention via ttlMs
 *   - checkpoints (save / load)
 *   - context assembly that returns verified / assumption / unresolved
 *   - secret redaction on every write
 *   - explainable retrieval scoring (key > value > tag)
 *
 * The store is never executed. The redactor is the only place that
 * decides what is allowed to be written.
 */

const fs = require('node:fs');
const crypto = require('node:crypto');
const { redact } = require('./redact');
const { recordPath, findFilenameVariant } = require('./paths');

const MEMORY_TYPES = new Set(['fact', 'decision', 'assumption', 'unresolved', 'evidence', 'preference']);
const VALID_TYPES = MEMORY_TYPES;

const REQUIRED = ['id', 'projectId', 'key', 'value', 'ts', 'type'];
const STRING_FIELDS = ['id', 'projectId', 'taskId', 'key', 'ts', 'type', 'sourceTaskId', 'verifiedBy'];

function validate(record) {
  if (!record || typeof record !== 'object') return 'record must be an object';
  for (const f of REQUIRED) {
    const v = record[f];
    // Absent, null and (for string fields) empty are all reported the same
    // way, so "missing field: key" is the single answer to "you did not give
    // me a key". This matters because `key` is the dedup + lookup identity
    // of a record: normalising an absent key would store the literal string
    // "undefined" and silently collapse every keyless write onto one record.
    if (v === undefined || v === null) return `missing field: ${f}`;
    if (f === 'value') continue; // any non-null value is acceptable
    if (typeof v !== 'string') return `field ${f} must be a non-empty string`;
    if (v.length === 0) return `missing field: ${f}`;
  }
  if (!VALID_TYPES.has(record.type)) return `unknown memory type: ${record.type}`;
  if (record.confidence != null) {
    if (typeof record.confidence !== 'number' || record.confidence < 0 || record.confidence > 1) {
      return 'confidence must be a number in [0, 1]';
    }
  }
  if (record.ttlMs != null) {
    if (typeof record.ttlMs !== 'number' || record.ttlMs < 0) return 'ttlMs must be a non-negative number';
  }
  const tags = record.tags;
  if (tags != null) {
    if (!Array.isArray(tags) || tags.some((t) => typeof t !== 'string')) {
      return 'tags must be an array of strings';
    }
  }
  return null;
}

function normalize(input, projectId, taskId) {
  const id = input.id || ('m_' + crypto.randomBytes(6).toString('hex'));
  const ts = input.ts || new Date().toISOString();
  const ttlMs = input.ttlMs || null;
  return {
    id,
    projectId,
    taskId: taskId || input.taskId || null,
    key: input.key == null ? null : String(input.key),
    value: input.value,
    tags: Array.isArray(input.tags) ? input.tags : [],
    type: input.type || 'fact',
    confidence: input.confidence ?? 1.0,
    verifiedBy: input.verifiedBy || null,
    sourceTaskId: input.sourceTaskId || (taskId || null),
    ts,
    expiresAt: ttlMs ? new Date(Date.parse(ts) + ttlMs).toISOString() : null,
  };
}

function normaliseKey(s) {
  return String(s).toLowerCase().replace(/\s+/g, ' ').trim();
}

function nearEqual(a, b) {
  if (a == null || b == null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a === 'string') return normaliseKey(a) === normaliseKey(b);
  if (typeof a === 'object') {
    return JSON.stringify(a) === JSON.stringify(b);
  }
  return a === b;
}

class Memory {
  constructor(rootDir) {
    this.root = rootDir;
    fs.mkdirSync(this.root, { recursive: true });
  }

  _file(projectId) {
    return recordPath(this.root, projectId || 'default', '.json', 'project id');
  }

  _checkpointFile(projectId) {
    return recordPath(this.root, projectId || 'default', '.checkpoint.json', 'project id');
  }

  /**
   * Read the raw file at `f`, distinguishing "absent" from "present but not
   * what this namespace writes".
   *
   * The three states matter separately:
   *   - absent        → nothing to protect
   *   - unparseable   → this namespace's own damaged file; it may be replaced
   *   - parsed, but
   *     not an array  → a foreign document; it may not be overwritten
   *
   * @returns {{missing: boolean, parsed?: boolean, body?: object, array?: boolean}}
   */
  _readRaw(f) {
    if (!fs.existsSync(f)) return { missing: true };
    try {
      const parsed = JSON.parse(fs.readFileSync(f, 'utf-8'));
      return { missing: false, parsed: true, body: parsed, array: Array.isArray(parsed) };
    } catch {
      return { missing: false, parsed: false };
    }
  }

  // ---- persistence with quarantine ----

  _readFile(f) {
    if (!fs.existsSync(f)) return [];
    try {
      const j = JSON.parse(fs.readFileSync(f, 'utf-8'));
      return Array.isArray(j) ? j : [];
    } catch {
      return [];
    }
  }

  _writeFile(f, records) {
    // The whole file is rewritten on every write, so a non-atomic write
    // risks losing every record in the store if the process dies
    // mid-write. The record set is staged next to the target and renamed
    // into place, which is atomic on every supported platform.
    const tmp = `${f}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 10)}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(records, null, 2));
      fs.renameSync(tmp, f);
    } catch (err) {
      try { fs.unlinkSync(tmp); } catch { /* ignore */ }
      throw err;
    }
  }

  _all(projectId) {
    const raw = this._readFile(this._file(projectId));
    const good = [];
    let quarantined = 0;
    for (const r of raw) {
      if (validate(r) === null) good.push(r);
      else quarantined += 1;
    }
    return { good, quarantined };
  }

  // ---- CRUD ----

  list(projectId) {
    const { good } = this._all(projectId);
    return this._purgeExpired(good);
  }

  get(id, projectId) {
    return this.list(projectId).find((r) => r.id === id) || null;
  }

  add(projectId, input, opts = {}) {
    // The key is the dedup + lookup identity of a record, so it is guarded
    // at the API boundary with the exact Phase 1 message. Without this the
    // record would be normalised with a null key and written under a shared
    // identity, silently collapsing unrelated writes onto one entry.
    if (!input || input.key == null || input.key === '') {
      throw new Error('memory.add: key is required');
    }
    // A project file is only ever written through the project id it belongs
    // to. Two names reach one file: a case-insensitive filesystem
    // (`ProjectX` / `projectx`), and a project id ending in `.checkpoint`,
    // whose record file is another project's checkpoint file. Writing either
    // would mix or destroy another project's records, so ownership is
    // verified before the first write. A file that cannot be parsed is
    // still rewritten: it is this project's own damaged file, and replacing
    // it is the documented recovery.
    const pid = projectId || 'default';
    const file = this._file(projectId);
    const raw = this._readRaw(file);
    const variant = findFilenameVariant(this.root, `${pid}.json`);
    if (raw.parsed && !raw.array) {
      const err = new Error(
        `memory.add: project id ${JSON.stringify(pid)} resolves to a file that already holds ` +
        `a non-record document; refusing to overwrite it`,
      );
      err.code = 'PROJECT_ID_CONFLICT';
      throw err;
    }
    if (variant) {
      const err = new Error(
        `memory.add: project id ${JSON.stringify(pid)} differs only by case from existing project ` +
        `${JSON.stringify(variant.slice(0, -'.json'.length))}; refusing to mix their records`,
      );
      err.code = 'PROJECT_ID_CONFLICT';
      throw err;
    }
    const normalised = normalize(input, projectId, opts.taskId);
    const error = validate(normalised);
    if (error) throw new Error(`memory.add: ${error}`);

    // redact before write
    const safe = redact(normalised);

    const { good } = this._all(projectId);
    if (opts.allowDuplicate !== true) {
      const existing = good.find((r) => r.key === safe.key);
      if (existing) {
        // Strict equality → exact dedup
        if (existing.value === safe.value) {
          if (opts.onNearDuplicate === 'merge') {
            // merge still updates tags/ts even when the value is identical
            existing.tags = Array.from(new Set([...(existing.tags || []), ...(safe.tags || [])]));
            existing.ts = safe.ts;
            this._writeFile(file, good);
            return existing;
          }
          return existing;
        }
        // Near-equal (e.g. differing case) — operator may ask us to merge
        if (nearEqual(existing.value, safe.value) && opts.onNearDuplicate === 'merge') {
          existing.tags = Array.from(new Set([...(existing.tags || []), ...(safe.tags || [])]));
          existing.ts = safe.ts;
          // keep the longer / more specific value
          const a = typeof existing.value === 'string' ? existing.value : JSON.stringify(existing.value);
          const b = typeof safe.value === 'string' ? safe.value : JSON.stringify(safe.value);
          if (b.length > a.length) existing.value = safe.value;
          this._writeFile(file, good);
          return existing;
        }
        // distinct value under the same key — keep both
      }
    }
    good.push(safe);
    this._writeFile(file, good);
    return safe;
  }

  update(id, projectId, patch) {
    const { good } = this._all(projectId);
    const idx = good.findIndex((r) => r.id === id);
    if (idx < 0) return null;
    const next = redact({ ...good[idx], ...patch, id, projectId, ts: good[idx].ts });
    const err = validate(next);
    if (err) throw new Error(`memory.update: ${err}`);
    good[idx] = next;
    this._writeFile(this._file(projectId), good);
    return next;
  }

  delete(id, projectId) {
    const { good } = this._all(projectId);
    const next = good.filter((r) => r.id !== id);
    if (next.length === good.length) return false;
    this._writeFile(this._file(projectId), next);
    return true;
  }

  // ---- retrieval ----

  async search(query, projectId) {
    if (typeof query !== 'string' || query.length === 0) {
      throw new Error('query required');
    }
    const q = query.toLowerCase();
    const recs = this.list(projectId);
    const scored = [];
    for (const r of recs) {
      let score = 0;
      if (r.key && r.key.toLowerCase().includes(q)) score += 3;
      const valueStr = typeof r.value === 'string' ? r.value : JSON.stringify(r.value);
      if (valueStr && valueStr.toLowerCase().includes(q)) score += 2;
      if (Array.isArray(r.tags) && r.tags.some((t) => String(t).toLowerCase().includes(q))) score += 1;
      if (score > 0) scored.push({ score, r });
    }
    scored.sort((a, b) => b.score - a.score || a.r.ts.localeCompare(b.r.ts));
    return scored.map((x) => ({
      id: x.r.id, key: x.r.key, type: x.r.type, tags: x.r.tags, score: x.score, ts: x.r.ts,
    }));
  }

  _purgeExpired(records) {
    const now = Date.now();
    return records.filter((r) => {
      if (!r.expiresAt) return true;
      return Date.parse(r.expiresAt) > now;
    });
  }

  // ---- checkpoints ----

  saveCheckpoint(projectId, snapshot) {
    if (!projectId) throw new Error('projectId required');
    if (!snapshot || typeof snapshot !== 'object') throw new Error('snapshot must be an object');
    const pid = projectId;
    // A checkpoint file is only ever written through the project id it
    // belongs to. The two aliasing cases are a case-variant project id
    // (one file on Windows/macOS, two on Linux) and a *project* named
    // `x.checkpoint`, whose record file is this checkpoint's file. Both are
    // refused before the write, so records are never destroyed by an id
    // that merely spells another id differently. A file that cannot be
    // parsed is still replaced: it is this project's own damaged checkpoint.
    const cpFile = this._checkpointFile(projectId);
    const raw = this._readRaw(cpFile);
    const variant = findFilenameVariant(this.root, `${pid}.checkpoint.json`);
    if (!raw.missing && raw.body != null && raw.body.projectId !== pid) {
      const err = new Error(
        `memory.saveCheckpoint: project id ${JSON.stringify(pid)} resolves to a checkpoint that ` +
        `belongs to project ${JSON.stringify(raw.body.projectId)}; refusing to overwrite it`,
      );
      err.code = 'PROJECT_ID_CONFLICT';
      throw err;
    }
    if (!raw.missing && raw.array) {
      const err = new Error(
        `memory.saveCheckpoint: project id ${JSON.stringify(pid)} resolves to a project record file; ` +
        `refusing to overwrite it`,
      );
      err.code = 'PROJECT_ID_CONFLICT';
      throw err;
    }
    if (variant) {
      const err = new Error(
        `memory.saveCheckpoint: project id ${JSON.stringify(pid)} differs only by case from ` +
        `project ${JSON.stringify(variant.slice(0, -'.checkpoint.json'.length))}; refusing to overwrite its checkpoint`,
      );
      err.code = 'PROJECT_ID_CONFLICT';
      throw err;
    }
    const safe = redact({
      projectId,
      ts: new Date().toISOString(),
      objective: snapshot.objective || null,
      completed: Array.isArray(snapshot.completed) ? snapshot.completed : [],
      pending: Array.isArray(snapshot.pending) ? snapshot.pending : [],
      decisions: Array.isArray(snapshot.decisions) ? snapshot.decisions : [],
      errors: Array.isArray(snapshot.errors) ? snapshot.errors : [],
      nextActions: Array.isArray(snapshot.nextActions) ? snapshot.nextActions : [],
    });
    fs.writeFileSync(this._checkpointFile(projectId), JSON.stringify(safe, null, 2));
    return safe;
  }

  loadCheckpoint(projectId) {
    const pid = projectId || 'default';
    const f = this._checkpointFile(projectId);
    if (!fs.existsSync(f)) return null;
    try {
      const parsed = JSON.parse(fs.readFileSync(f, 'utf-8'));
      // The checkpoint served must be the one this project id asked for. On
      // a case-insensitive filesystem a case-variant id reaches another
      // project's checkpoint file; the embedded project id is the tiebreaker.
      if (!parsed || typeof parsed !== 'object' || parsed.projectId !== pid) return null;
      return parsed;
    }
    catch { return null; }
  }

  // ---- context assembly ----

  async assembleContext({ projectId, taskId, query, maxItems = 20 }) {
    if (!projectId) throw new Error('projectId required');
    const checkpoint = this.loadCheckpoint(projectId);
    const projectRecords = this.list(projectId);
    const taskRecords = taskId
      ? projectRecords.filter((r) => r.taskId === taskId)
      : [];
    const all = query
      ? await this.search(query, projectId)
      : projectRecords.map((r) => ({ id: r.id, key: r.key, type: r.type, tags: r.tags, score: 0, ts: r.ts }));

    const byType = { verified: [], assumption: [], unresolved: [], other: [] };
    for (const r of projectRecords) {
      if (r.type === 'fact' || r.type === 'evidence' || r.type === 'decision') byType.verified.push(r);
      else if (r.type === 'assumption') byType.assumption.push(r);
      else if (r.type === 'unresolved') byType.unresolved.push(r);
      else byType.other.push(r);
    }

    // A context assembled for one task must not carry another task's
    // task-scoped records. Project-wide records (taskId null) belong to
    // every task; records bound to a different task do not.
    const scoped = taskId
      ? (r) => r.taskId == null || r.taskId === taskId
      : (r) => r.taskId == null;

    return {
      projectId,
      taskId: taskId || null,
      query: query || null,
      checkpoint: checkpoint || null,
      matches: all.slice(0, maxItems).map((m) => m.id || m),
      verified: byType.verified.filter(scoped).slice(0, maxItems),
      assumption: byType.assumption.filter(scoped).slice(0, maxItems),
      unresolved: byType.unresolved.filter(scoped).slice(0, maxItems),
      other: byType.other.filter(scoped).slice(0, maxItems),
      taskScoped: taskRecords.slice(0, maxItems),
    };
  }
}

module.exports = { Memory, validate, normalize, MEMORY_TYPES, REQUIRED, STRING_FIELDS };
