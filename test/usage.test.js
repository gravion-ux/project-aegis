'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Budget, BudgetManager } = require('../aegis/usage');

test('budget: record accumulates input/output chars', () => {
  const b = new Budget({ maxInputChars: 1000, maxOutputChars: 1000 });
  b.record({ input: 100, output: 50 });
  b.record({ input: 200, output: 25 });
  const s = b.summary();
  assert.equal(s.inputChars, 300);
  assert.equal(s.outputChars, 75);
  assert.equal(s.exceeded, false);
});

test('budget: exceeding input cap throws BUDGET_EXCEEDED', () => {
  const b = new Budget({ maxInputChars: 100 });
  assert.throws(() => b.record({ input: 200, output: 0 }), (err) => err.code === 'BUDGET_EXCEEDED');
});

test('budget: wouldExceed predicts without mutating', () => {
  const b = new Budget({ maxInputChars: 100 });
  assert.equal(b.wouldExceed({ input: 50 }), null);
  assert.equal(b.wouldExceed({ input: 150 }), 'inputChars');
  assert.equal(b.summary().inputChars, 0, 'state unchanged');
});

test('budget: pricing is reported when configured', () => {
  const b = new Budget({ pricing: { inputPer1k: 0.001, outputPer1k: 0.002, currency: 'USD' } });
  b.record({ input: 1000, output: 1000 });
  const s = b.summary();
  assert.equal(s.pricingKnown, true);
  assert.ok(s.estimatedCost > 0);
});

test('budget: pricing is "unknown" when not configured', () => {
  const b = new Budget();
  b.record({ input: 1000, output: 1000 });
  const s = b.summary();
  assert.equal(s.pricingKnown, false);
  assert.equal(s.estimatedCost, null, 'never invents a cost');
});

test('budget: token source is tracked', () => {
  const b = new Budget();
  b.record({ input: 10, output: 10, tokens: 5, tokenSource: 'reported' });
  assert.equal(b.summary().tokens, 5);
  assert.equal(b.summary().tokenSource, 'reported');
});

test('budget: token source stays "unknown" when the provider reports nothing', () => {
  const b = new Budget();
  b.record({ input: 10, output: 10 });
  assert.equal(b.summary().tokenSource, 'unknown');
  assert.equal(b.summary().tokens, 0);
});

test('BudgetManager: per-task budgets are tracked separately', () => {
  const m = new BudgetManager();
  m.record('t1', { input: 10, output: 5 });
  m.record('t2', { input: 20, output: 5 });
  const s = m.summary();
  const t1 = s.perTask.find((x) => x.taskId === 't1');
  const t2 = s.perTask.find((x) => x.taskId === 't2');
  assert.equal(t1.inputChars, 10);
  assert.equal(t2.inputChars, 20);
});

test('BudgetManager: global budget blocks further usage', () => {
  const m = new BudgetManager();
  m.global.limits.inputChars = 50;
  m.record('t1', { input: 40, output: 0 });
  assert.throws(() => m.record('t1', { input: 40, output: 0 }), (err) => err.code === 'BUDGET_EXCEEDED');
});

test('BudgetManager: forTask creates a stable budget object', () => {
  const m = new BudgetManager();
  const a = m.forTask('t9');
  const b = m.forTask('t9');
  assert.equal(a, b);
});