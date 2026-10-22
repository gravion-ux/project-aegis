'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { STATES, canTransition, isTerminal, assertTransition } = require('../aegis/states');

test('states: terminal states', () => {
  assert.ok(isTerminal(STATES.SUCCEEDED));
  assert.ok(isTerminal(STATES.FAILED));
  assert.ok(isTerminal(STATES.CANCELLED));
  assert.ok(!isTerminal(STATES.RUNNING));
  assert.ok(!isTerminal(STATES.QUEUED));
});

test('states: valid transitions', () => {
  assert.ok(canTransition(STATES.QUEUED, STATES.READY));
  assert.ok(canTransition(STATES.READY, STATES.RUNNING));
  assert.ok(canTransition(STATES.RUNNING, STATES.SUCCEEDED));
  assert.ok(canTransition(STATES.RUNNING, STATES.FAILED));
  assert.ok(canTransition(STATES.FAILED, STATES.RETRYING));
  assert.ok(canTransition(STATES.RETRYING, STATES.RUNNING));
});

test('states: terminal states are sinks', () => {
  for (const t of [STATES.SUCCEEDED, STATES.CANCELLED]) {
    for (const target of Object.values(STATES)) {
      if (t === target) continue;
      assert.equal(canTransition(t, target), false, `${t} → ${target} should be rejected`);
    }
  }
});

test('states: assertTransition throws on invalid', () => {
  assert.throws(() => assertTransition(STATES.SUCCEEDED, STATES.RUNNING), /invalid transition/);
  assert.throws(() => assertTransition(STATES.QUEUED, STATES.SUCCEEDED), /invalid transition/);
});
