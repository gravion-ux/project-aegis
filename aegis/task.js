'use strict';

/**
 * Task model.
 *
 * A task carries an immutable id, a title, a goal, a role, a state,
 * a creation timestamp, a list of state transitions, and free-form
 * input/output/evidence. State transitions are validated against
 * `states.js`. Every successful transition appends a record to
 * `transitions` and bumps `updatedAt`.
 */

const crypto = require('node:crypto');
const { STATES, assertTransition } = require('./states');

function newTaskId() {
  return 't_' + crypto.randomBytes(8).toString('hex');
}

function now() { return new Date().toISOString(); }

class Task {
  constructor({ id, title, role, goal, input }) {
    this.id = id || newTaskId();
    this.title = title || '(untitled)';
    this.role = role || 'coding';
    this.goal = goal || '';
    this.input = input || {};
    this.state = STATES.QUEUED;
    this.createdAt = now();
    this.updatedAt = now();
    this.transitions = [{ ts: this.createdAt, from: null, to: STATES.QUEUED, note: 'created' }];
    this.output = null;
    this.evidence = [];
    this.error = null;
    this.retries = 0;
  }

  transition(nextState, opts = {}) {
    assertTransition(this.state, nextState);
    const ts = now();
    const record = {
      ts,
      from: this.state,
      to: nextState,
      note: opts.note || null,
      actor: opts.actor || 'system',
    };
    this.state = nextState;
    this.transitions.push(record);
    this.updatedAt = ts;
    if (nextState === STATES.FAILED) {
      this.error = opts.error || this.error;
    } else if (nextState === STATES.RETRYING) {
      this.retries += 1;
    }
    return record;
  }

  attachOutput(output) {
    this.output = output;
    this.updatedAt = now();
  }

  addEvidence(evidence) {
    this.evidence.push({ ts: now(), ...(evidence || {}) });
    this.updatedAt = now();
  }

  toJSON() {
    return {
      id: this.id,
      title: this.title,
      role: this.role,
      goal: this.goal,
      input: this.input,
      state: this.state,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      transitions: this.transitions,
      output: this.output,
      evidence: this.evidence,
      error: this.error,
      retries: this.retries,
    };
  }

  static fromJSON(obj) {
    if (!obj || !obj.id) throw new Error('Task.fromJSON: missing id');
    const t = new Task({
      id: obj.id, title: obj.title, role: obj.role, goal: obj.goal, input: obj.input,
    });
    t.state = obj.state || STATES.QUEUED;
    t.createdAt = obj.createdAt || t.createdAt;
    t.updatedAt = obj.updatedAt || t.updatedAt;
    t.transitions = Array.isArray(obj.transitions) ? obj.transitions : t.transitions;
    t.output = obj.output || null;
    t.evidence = Array.isArray(obj.evidence) ? obj.evidence : [];
    t.error = obj.error || null;
    t.retries = obj.retries || 0;
    return t;
  }
}

module.exports = { Task };
