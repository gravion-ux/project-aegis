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
    this.estimatedCost = 0;
    this.currency = opts.currency || 'USD';
    this.limits = {
      inputChars:   opts.maxInputChars   || null,
      outputChars:  opts.maxOutputChars  || null,
      tokens:       opts.maxTokens       || null,
      estimatedCost:opts.maxCost         || null,
    };
    this.pricing = opts.pricing || null; // { inputPer1k, outputPer1k, currency }
  }

  /**
   * Record usage. `tokens` and `tokenSource` are optional.
   * Returns the running totals; throws if the budget is exceeded.
   */
  record({ input = 0, output = 0, tokens = null, tokenSource = null } = {}) {
    this.inputChars += input;
    this.outputChars += output;
    if (typeof tokens === 'number') {
      this.tokens += tokens;
      this.tokenSource = tokenSource || this.tokenSource;
    }
    if (this.pricing) {
      const inCost = (input  / 1000) * Number(this.pricing.inputPer1k  || 0);
      const outCost = (output / 1000) * Number(this.pricing.outputPer1k || 0);
      this.estimatedCost += inCost + outCost;
    }
    if (this.exceeded()) {
      const err = new Error('budget exceeded');
      err.code = 'BUDGET_EXCEEDED';
      err.summary = this.summary();
      throw err;
    }
    return this.summary();
  }

  exceeded() {
    const L = this.limits;
    if (L.inputChars != null && this.inputChars > L.inputChars) return true;
    if (L.outputChars != null && this.outputChars > L.outputChars) return true;
    if (L.tokens != null && this.tokens > L.tokens) return true;
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

  summary() {
    return {
      inputChars: this.inputChars,
      outputChars: this.outputChars,
      tokens: this.tokens,
      tokenSource: this.tokenSource,
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
  constructor() {
    this.global = new Budget();
    this.byTask = new Map();
  }

  forTask(taskId, opts = {}) {
    let b = this.byTask.get(taskId);
    if (!b) {
      b = new Budget(opts);
      this.byTask.set(taskId, b);
    }
    return b;
  }

  record(taskId, usage) {
    // preflight at the global level first
    const trial = { inputChars: usage.input || 0, outputChars: usage.output || 0, tokens: usage.tokens || 0 };
    if (this.global.wouldExceed(trial)) {
      const err = new Error('global budget exceeded');
      err.code = 'BUDGET_EXCEEDED';
      err.summary = this.global.summary();
      throw err;
    }
    this.global.record(usage);
    this.forTask(taskId).record(usage);
  }

  summary() {
    return { global: this.global.summary(), perTask: [...this.byTask.entries()].map(([id, b]) => ({ taskId: id, ...b.summary() })) };
  }
}

module.exports = { Budget, BudgetManager };
