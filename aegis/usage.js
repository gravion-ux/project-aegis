'use strict';

/**
 * Resource and cost manager.
 *
 * Tracks per-task and global usage budgets. Distinguishes between
 * provider-reported usage (real token counts) and estimated usage
 * (character counts when no tokenizer is available).
 *
 * Pricing is loaded from the config (operator-supplied). If a model
 * has no configured price, `pricing: 'unknown'` is reported — never
 * an invented number.
 */

class Budget {
  constructor(opts = {}) {
    this.inputChars = 0;
    this.outputChars = 0;
    this.tokens = 0;
    this.tokenSource = 'unknown';
    this.attempts = 0;
    this.estimatedCost = 0;
    this.currency = opts.currency || 'USD';
    this.limits = {
      inputChars:   opts.maxInputChars   || null,
      outputChars:  opts.maxOutputChars  || null,
      tokens:       opts.maxTokens       || null,
      estimatedCost:opts.maxCost         || null,
      attempts:     opts.maxAttempts     || null,
    };
    this.pricing = opts.pricing || null; // { inputPer1k, outputPer1k, currency }
  }

  /**
   * Validate a usage delta. Non-finite or negative numbers are refused:
   * a NaN would make every later comparison false and silently disable the
   * limits, which is a budget-evasion path rather than a typo.
   */
  _validateDelta({ input = 0, output = 0, tokens = null } = {}) {
    for (const [name, v] of [['input', input], ['output', output]]) {
      if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
        const err = new Error(`budget: ${name} must be a finite non-negative number (got ${String(v)})`);
        err.code = 'INVALID_USAGE';
        throw err;
      }
    }
    if (tokens != null && (typeof tokens !== 'number' || !Number.isFinite(tokens) || tokens < 0)) {
      const err = new Error(`budget: tokens must be a finite non-negative number (got ${String(tokens)})`);
      err.code = 'INVALID_USAGE';
      throw err;
    }
  }

  /**
   * Record usage. `tokens` and `tokenSource` are optional.
   *
   * The limit is checked **before** anything is mutated, so a refused call
   * leaves the budget exactly as it was. A budget that charges for work it
   * has already rejected is not a limit, it is a counter.
   *
   * `attempt: true` counts one agent/provider attempt rather than tokens.
   * That is how a retry loop is bounded by the budget instead of only by
   * the orchestrator's iteration cap.
   *
   * @returns {object} the running totals
   */
  record({ input = 0, output = 0, tokens = null, tokenSource = null, attempt = false } = {}) {
    this._validateDelta({ input, output, tokens });

    const addTokens = typeof tokens === 'number' ? tokens : 0;
    const nextAttempts = this.attempts + (attempt ? 1 : 0);
    const costDelta = this.pricing
      ? (input / 1000) * Number(this.pricing.inputPer1k || 0)
        + (output / 1000) * Number(this.pricing.outputPer1k || 0)
      : 0;
    const nextCost = this.estimatedCost + costDelta;

    const L = this.limits;
    const over =
      (L.inputChars    != null && this.inputChars + input   > L.inputChars) ||
      (L.outputChars   != null && this.outputChars + output > L.outputChars) ||
      (L.tokens        != null && this.tokens + addTokens   > L.tokens) ||
      (L.attempts      != null && nextAttempts              > L.attempts) ||
      (L.estimatedCost != null && this.pricing && nextCost  > L.estimatedCost);

    if (over) {
      const err = new Error('budget exceeded');
      err.code = 'BUDGET_EXCEEDED';
      err.summary = this.summary(); // the *unchanged* totals
      throw err;
    }

    // Only now is the budget mutated.
    this.inputChars += input;
    this.outputChars += output;
    if (typeof tokens === 'number') {
      this.tokens += tokens;
      this.tokenSource = tokenSource || this.tokenSource;
    }
    this.attempts = nextAttempts;
    this.estimatedCost = nextCost;
    return this.summary();
  }

  exceeded() {
    const L = this.limits;
    if (L.inputChars != null && this.inputChars > L.inputChars) return true;
    if (L.outputChars != null && this.outputChars > L.outputChars) return true;
    if (L.tokens != null && this.tokens > L.tokens) return true;
    if (L.attempts != null && this.attempts > L.attempts) return true;
    if (L.estimatedCost != null && this.pricing && this.estimatedCost > L.estimatedCost) return true;
    return false;
  }

  /**
   * Preflight check: would recording this much usage exceed the budget?
   */
  wouldExceed({ input = 0, output = 0, tokens = null } = {}) {
    const L = this.limits;
    if (L.inputChars   != null && this.inputChars + input   > L.inputChars)   return 'inputChars';
    if (L.outputChars  != null && this.outputChars + output > L.outputChars)  return 'outputChars';
    if (L.tokens       != null && this.tokens     + (tokens || 0) > L.tokens)  return 'tokens';
    if (L.estimatedCost != null && this.pricing) {
      const est = (input / 1000) * Number(this.pricing.inputPer1k || 0)
                + (output / 1000) * Number(this.pricing.outputPer1k || 0);
      if (this.estimatedCost + est > L.estimatedCost) return 'estimatedCost';
    }
    return null;
  }

  /**
   * True when the budget has no headroom left, so no further work should
   * start.
   *
   * This is deliberately stricter than `exceeded()`: reaching a limit means
   * there is nothing left to spend, so another attempt must not begin.
   * `exceeded()` answers "is the recorded usage over a limit", which is a
   * reporting question; this one is a gate.
   */
  exhausted() {
    const L = this.limits;
    if (L.inputChars != null && this.inputChars >= L.inputChars) return true;
    if (L.outputChars != null && this.outputChars >= L.outputChars) return true;
    if (L.tokens != null && this.tokens >= L.tokens) return true;
    if (L.attempts != null && this.attempts >= L.attempts) return true;
    if (L.estimatedCost != null && this.pricing && this.estimatedCost >= L.estimatedCost) return true;
    return false;
  }

  /**
   * Refuse to start work when the budget has no headroom left.
   *
   * Used as a gate before each attempt, so a task cannot begin when the
   * budget is already spent, and a retry loop cannot run past a limit that
   * the budget is meant to enforce.
   */
  guard() {
    if (this.exhausted()) {
      const err = new Error('budget limit reached');
      err.code = 'BUDGET_EXCEEDED';
      err.summary = this.summary(); // the *unchanged* totals
      throw err;
    }
    return false;
  }

  summary() {
    return {
      inputChars: this.inputChars,
      outputChars: this.outputChars,
      tokens: this.tokens,
      tokenSource: this.tokenSource,
      attempts: this.attempts,
      estimatedCost: this.pricing ? Number(this.estimatedCost.toFixed(6)) : null,
      pricingKnown: !!this.pricing,
      currency: this.currency,
      limits: { ...this.limits },
      exceeded: this.exceeded(),
    };
  }
}

/**
 * A simple global registry of per-task Budgets. The orchestrator
 * and router use this to enforce limits across all tasks.
 */
class BudgetManager {
  constructor(opts = {}) {
    this.global = new Budget(opts);
    this.byTask = new Map();
  }

  /**
   * Refuse to start work when the global budget, or the budget for this
   * task, has no headroom left.
   */
  guard(taskId = null) {
    this.global.guard();
    if (taskId != null) {
      const b = this.byTask.get(taskId);
      if (b) b.guard();
    }
    return false;
  }

  /**
   * Get (or create) the budget for a task.
   *
   * Limits supplied here are applied even when the budget already exists —
   * otherwise a limit set after the first `record()` would be silently
   * ignored, and the task would run with no limit at all.
   */
  forTask(taskId, opts = {}) {
    let b = this.byTask.get(taskId);
    if (!b) {
      b = new Budget(opts);
      this.byTask.set(taskId, b);
      return b;
    }
    if (opts && Object.keys(opts).length > 0) {
      if (opts.maxInputChars != null) b.limits.inputChars = opts.maxInputChars;
      if (opts.maxOutputChars != null) b.limits.outputChars = opts.maxOutputChars;
      if (opts.maxTokens != null) b.limits.tokens = opts.maxTokens;
      if (opts.maxCost != null) b.limits.estimatedCost = opts.maxCost;
      if (opts.maxAttempts != null) b.limits.attempts = opts.maxAttempts;
      if (opts.pricing != null) b.pricing = opts.pricing;
      if (opts.currency != null) b.currency = opts.currency;
    }
    return b;
  }

  record(taskId, usage) {
    // Preflight against BOTH the global and the per-task budget before
    // anything is recorded. `wouldExceed` takes {input, output, tokens},
    // so the trial object must use those exact keys.
    const trial = { input: usage.input || 0, output: usage.output || 0, tokens: usage.tokens || 0 };
    if (this.global.wouldExceed(trial)) {
      const err = new Error('global budget exceeded');
      err.code = 'BUDGET_EXCEEDED';
      err.summary = this.global.summary();
      throw err;
    }
    const taskBudget = this.forTask(taskId);
    if (taskBudget.wouldExceed(trial)) {
      const err = new Error('task budget exceeded');
      err.code = 'BUDGET_EXCEEDED';
      err.summary = taskBudget.summary();
      throw err;
    }
    // Neither record() can throw now — both check before mutating.
    this.global.record(usage);
    taskBudget.record(usage);
  }

  summary() {
    return { global: this.global.summary(), perTask: [...this.byTask.entries()].map(([id, b]) => ({ taskId: id, ...b.summary() })) };
  }
}

module.exports = { Budget, BudgetManager };
