'use strict';

/**
 * Generic HTTP provider.
 *
 * POSTs the request as JSON to `baseUrl` and returns the response.
 * No API key is read from the request. Authentication headers can be
 * configured via `authHeader` (a static string like `Bearer …`); do
 * not put secrets in source code — read them from an env var.
 *
 * This provider is the safe, generic way to talk to any local
 * model server (Ollama / LM Studio / llama.cpp / vLLM) without
 * committing to one provider's wire format.
 *
 * The response shape is permissive: { text, model, finishReason,
 * usage }. The provider looks for the response in `response.text`,
 * `response.content`, `response.message.content`, or the raw body —
 * whichever is present.
 */

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');
const { assertRequest, ProviderError } = require('./base');
const { redactString } = require('../redact');

// A model server that streams an unbounded body would otherwise be able
// to exhaust this process's memory. 8 MiB is far above any realistic
// chat completion.
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

class HttpProvider {
  constructor(opts = {}) {
    if (!opts.baseUrl) {
      throw new Error('HttpProvider: baseUrl is required');
    }
    this.name = opts.name || 'http';
    this.baseUrl = opts.baseUrl;
    this.model = opts.model || 'unknown';
    this.authHeader = opts.authHeader || null;
    this.timeoutMs = opts.timeoutMs || 30_000;
    this.maxResponseBytes = opts.maxResponseBytes || MAX_RESPONSE_BYTES;
    this._totalInput = 0;
    this._totalOutput = 0;
    this._totalTokens = 0;
    this._tokenSource = 'unknown';
  }

  capabilities() {
    return { chat: true, embeddings: false, toolUse: false, vision: false, streaming: false };
  }

  async complete(request) {
    assertRequest(request);
    const url = this.baseUrl;
    const headers = { 'content-type': 'application/json', accept: 'application/json' };
    if (this.authHeader) headers.authorization = this.authHeader;
    const body = JSON.stringify({ model: this.model, messages: request.messages, ...(request.options || {}) });

    const text = await postJson(url, body, headers, this.timeoutMs, this.maxResponseBytes);
    const parsed = safeJson(text);
    const out = extractTextAndUsage(parsed, text);

    this._totalInput += request.messages.reduce((n, m) => n + m.content.length, 0);
    this._totalOutput += out.text.length;
    if (out.usage && out.usage.total != null) {
      this._totalTokens += out.usage.total;
      this._tokenSource = 'reported';
    } else {
      this._tokenSource = 'estimated';
    }
    return { text: out.text, model: this.model, finishReason: 'stop', usage: out.usage, raw: parsed };
  }

  usage() {
    return {
      input: this._totalInput,
      output: this._totalOutput,
      total: this._totalInput + this._totalOutput,
      unit: 'chars',
      tokens: this._totalTokens,
      tokenSource: this._tokenSource,
    };
  }

  pricing() {
    return null; // unknown; operator must configure per-model pricing
  }
}

function postJson(urlText, body, headers, timeoutMs, maxResponseBytes = MAX_RESPONSE_BYTES) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlText); } catch (e) { return reject(new ProviderError(`bad url: ${e.message}`)); }
    const transport = u.protocol === 'https:' ? https : http;
    let settled = false;
    const done = (fn, v) => { if (settled) return; settled = true; fn(v); };
    const req = transport.request({
      method: 'POST',
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      headers: { ...headers, 'content-length': Buffer.byteLength(body) },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > maxResponseBytes) {
          req.destroy();
          done(reject, new ProviderError(
            `response exceeded ${maxResponseBytes} bytes`,
            { retryable: false },
          ));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf-8');
        // The error body is redacted before it becomes an error message:
        // a server that echoes the request headers must not be able to
        // leak the auth header into a log line.
        if (res.statusCode >= 500) {
          return done(reject, new ProviderError(`server ${res.statusCode}: ${redactString(text.slice(0, 500))}`, { retryable: true }));
        }
        if (res.statusCode >= 400) {
          return done(reject, new ProviderError(`client ${res.statusCode}: ${redactString(text.slice(0, 500))}`));
        }
        done(resolve, text);
      });
    });
    req.on('timeout', () => req.destroy(new ProviderError('timeout', { retryable: true })));
    req.on('error', (err) => done(reject, new ProviderError(`http error: ${redactString(err.message)}`, { retryable: true })));
    req.end(body);
  });
}

function safeJson(text) {
  if (!text) return null;
  try { return JSON.parse(text); } catch { return text; }
}

function extractTextAndUsage(parsed, rawText) {
  let text = '';
  let usage = null;
  if (parsed && typeof parsed === 'object') {
    if (typeof parsed.text === 'string') text = parsed.text;
    else if (typeof parsed.content === 'string') text = parsed.content;
    else if (parsed.message && typeof parsed.message.content === 'string') text = parsed.message.content;
    else if (parsed.choices && Array.isArray(parsed.choices) && parsed.choices[0]) {
      const c = parsed.choices[0];
      if (c.message && typeof c.message.content === 'string') text = c.message.content;
      else if (typeof c.text === 'string') text = c.text;
    }
    if (parsed.usage && typeof parsed.usage === 'object') {
      const i = Number(parsed.usage.prompt_tokens || parsed.usage.input_tokens || 0);
      const o = Number(parsed.usage.completion_tokens || parsed.usage.output_tokens || 0);
      const t = Number(parsed.usage.total_tokens || (i + o) || 0);
      usage = { input: i, output: o, total: t };
    }
  }
  if (!text) text = typeof rawText === 'string' ? rawText : '';
  return { text, usage };
}

module.exports = { HttpProvider, extractTextAndUsage };
