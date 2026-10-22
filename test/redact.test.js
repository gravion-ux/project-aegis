'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { redact, redactString } = require('../aegis/redact');

test('redact: bearer token', () => {
  assert.equal(redactString('Authorization: Bearer abc.def.ghi'),
    'Authorization: Bearer [REDACTED]');
});

test('redact: api_key=...', () => {
  assert.equal(redactString('api_key=sk-12345 something'),
    'api_key: [REDACTED] something');
});

test('redact: password: foo', () => {
  assert.equal(redactString('password: hunter2 nope'),
    'password: [REDACTED] nope');
});

test('redact: secret: xxx', () => {
  assert.equal(redactString('secret = yyy'),
    'secret: [REDACTED]');
});

test('redact: object is recursively redacted', () => {
  const out = redact({ headers: { authorization: 'Bearer abc' }, msg: 'token: x' });
  assert.equal(out.headers.authorization, 'Bearer [REDACTED]');
  assert.equal(out.msg, 'token: [REDACTED]');
});

test('redact: array is recursively redacted', () => {
  const out = redact(['Authorization: Bearer abc', 'safe', { config: 'api_key=secretvalue' }]);
  assert.equal(out[0], 'Authorization: Bearer [REDACTED]');
  assert.equal(out[1], 'safe');
  // The object value is a string; if it contains a recognised `key=value`
  // pattern, the value is redacted. The property name itself is preserved.
  assert.equal(out[2].config, 'api_key: [REDACTED]');
});

test('redact: non-strings are left alone', () => {
  assert.equal(redact(42), 42);
  assert.equal(redact(null), null);
  assert.equal(redact(undefined), undefined);
  assert.equal(redact(true), true);
});
