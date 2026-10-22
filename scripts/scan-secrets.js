'use strict';

/**
 * Credential scan for the tracked tree.
 *
 * Run locally with:  node scripts/scan-secrets.js
 * Run in CI by the "Assert no credential is present in the tracked tree" step.
 *
 * The rules are deliberately narrow. A broad "looks like a secret" regex
 * produces false positives on the very test fixtures that exist to prove
 * redaction works, and a scanner that cries wolf gets deleted. These patterns
 * match credential *shapes* — a provider key format, a PEM private key
 * header, a long high-entropy bearer token — and ignore short, obviously
 * synthetic strings.
 *
 * Files under test/ are scanned too, but with the synthetic fixtures the
 * suite deliberately uses marked as allowed (see ALLOWED_TEST_FIXTURES).
 * Those are literal placeholder strings, not credentials.
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

const RULES = [
  { id: 'openai-style-key', re: /\bsk-[A-Za-z0-9]{32,}\b/g },
  { id: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
  { id: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'private-key-block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: 'bearer-token', re: /\bBearer\s+[A-Za-z0-9._-]{40,}/g },
];

const SCAN_EXT = new Set(['.js', '.mjs', '.cjs', '.json', '.yml', '.yaml', '.md', '.sh', '.txt', '.example']);

// Directories that never contain source we ship.
const SKIP_DIRS = new Set(['.git', 'node_modules', 'state', 'data', 'logs', 'coverage']);

// Synthetic strings that the test suite uses on purpose to prove that the
// redactor works. Each is a placeholder with no entropy.
const ALLOWED_TEST_FIXTURES = [
  'sk-abcdefghijklmnopqrst',
  'sk-live-abc123def',
];

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.github') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out);
    } else if (entry.isFile()) {
      if (SCAN_EXT.has(path.extname(entry.name))) out.push(full);
    }
  }
  return out;
}

function isAllowedFixture(hit) {
  // Exact match only. A substring check would let a real credential that
  // merely *starts with* a known fixture through — which is exactly the
  // shape of the bug this scanner exists to catch.
  return ALLOWED_TEST_FIXTURES.includes(hit);
}

function scan() {
  const findings = [];
  for (const file of walk(ROOT)) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    for (const rule of RULES) {
      // fresh regex per file: the global flag keeps lastIndex between calls
      const re = new RegExp(rule.re.source, rule.re.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        if (isAllowedFixture(m[0])) continue;
        const line = text.slice(0, m.index).split('\n').length;
        findings.push({
          file: path.relative(ROOT, file).split(path.sep).join('/'),
          line,
          rule: rule.id,
          match: m[0].slice(0, 12) + '...',
        });
        if (m[0].length === 0) re.lastIndex += 1;
      }
    }
  }
  return findings;
}

function main() {
  const findings = scan();
  if (findings.length) {
    console.error(`::error::${findings.length} credential-shaped string(s) found in the tree:`);
    for (const f of findings) {
      console.error(`  ${f.file}:${f.line}  ${f.rule}  ${f.match}`);
    }
    process.exit(1);
  }
  console.log(`no credential-shaped strings found (${ALLOWED_TEST_FIXTURES.length} known test fixture(s) allowed)`);
}

if (require.main === module) main();

module.exports = { scan, RULES, ALLOWED_TEST_FIXTURES };
