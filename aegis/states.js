'use strict';

/**
 * Project AEGIS — task states and transitions.
 *
 * The set of states and the allowed transitions are the only place in
 * the codebase that defines the lifecycle. Code that mutates a Task's
 * state MUST go through `canTransition` and `assertTransition`.
 */

const STATES = Object.freeze({
  QUEUED: 'QUEUED',
  READY: 'READY',
  RUNNING: 'RUNNING',
  WAITING_FOR_APPROVAL: 'WAITING_FOR_APPROVAL',
  RETRYING: 'RETRYING',
  SUCCEEDED: 'SUCCEEDED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
  BLOCKED: 'BLOCKED',
});

const TERMINAL = new Set([STATES.SUCCEEDED, STATES.FAILED, STATES.CANCELLED]);

const ALLOWED = {
  [STATES.QUEUED]:              new Set([STATES.READY, STATES.CANCELLED, STATES.BLOCKED]),
  [STATES.READY]:               new Set([STATES.RUNNING, STATES.CANCELLED, STATES.BLOCKED]),
  [STATES.RUNNING]:             new Set([STATES.SUCCEEDED, STATES.FAILED, STATES.CANCELLED, STATES.WAITING_FOR_APPROVAL, STATES.BLOCKED]),
  [STATES.WAITING_FOR_APPROVAL]:new Set([STATES.RUNNING, STATES.CANCELLED, STATES.BLOCKED]),
  [STATES.RETRYING]:            new Set([STATES.RUNNING, STATES.CANCELLED, STATES.FAILED]),
  [STATES.SUCCEEDED]:           new Set(),
  [STATES.FAILED]:              new Set([STATES.RETRYING]),
  [STATES.CANCELLED]:           new Set(),
  [STATES.BLOCKED]:             new Set([STATES.READY, STATES.CANCELLED]),
};

function canTransition(from, to) {
  if (!ALLOWED[from]) return false;
  return ALLOWED[from].has(to);
}

function assertTransition(from, to) {
  if (!canTransition(from, to)) {
    const err = new Error(`invalid transition ${from} → ${to}`);
    err.code = 'INVALID_TRANSITION';
    throw err;
  }
}

function isTerminal(state) {
  return TERMINAL.has(state);
}

module.exports = { STATES, ALLOWED, canTransition, assertTransition, isTerminal };
