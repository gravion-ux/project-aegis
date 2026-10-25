'use strict';

/**
 * Path safety helpers.
 *
 * AEGIS turns caller-supplied identifiers — task ids, project ids — into
 * filenames. Without a check, an identifier like `../../etc/passwd` becomes
 * a path outside the state directory, and the read/write lands wherever the
 * process can reach.
 *
 * Two independent checks are applied, and both must pass:
 *
 *   1. `isSafeIdentifier` — the identifier cannot contain a path separator,
 *      cannot be absolute, cannot be a relative-directory token, and cannot
 *      contain NUL. This produces a clear, actionable error.
 *   2. `resolveWithin` — the *resolved* path is compared against the root.
 *      This is the actual security boundary: it holds even if the
 *      identifier rules are relaxed in future, and it catches cases the
 *      string rules miss (Windows drive-relative paths, UNC paths, and any
 *      platform-specific normalisation).
 *
 * The identifier rules reject *traversal*, not a naming convention. The one
 * extra restriction they do impose is portability: characters that cannot
 * form a filename on every supported platform are refused, so the same
 * identifier behaves identically on Linux, macOS and Windows instead of
 * succeeding on one platform and failing with a raw OS error on another.
 */

const path = require('node:path');

const MAX_IDENTIFIER_LENGTH = 255;

// Characters that are legal in a POSIX filename but not in a Windows one.
const WINDOWS_RESERVED_CHARS = /[<>:"/\\|?*]/;
// ASCII control characters are rejected on every platform.
const CONTROL_CHARS = /[\x00-\x1F\x7F]/;
// Device names that Windows reserves. `CON.json` is as reserved as `CON`,
// because the name is what matters, not the extension.
const WINDOWS_DEVICE_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;

function invalidIdentifier(id, label) {
  const err = new Error(`${label} is not a valid identifier: ${JSON.stringify(String(id))}`);
  err.code = 'INVALID_ID';
  return err;
}

/**
 * True when `id` cannot be used to escape a directory.
 *
 * Rejects: non-strings, empty strings, over-long strings, NUL bytes, the
 * relative-directory tokens `.` and `..`, anything containing `/` or `\`,
 * absolute paths, Windows drive-relative paths such as `C:foo`, control
 * characters, the characters Windows reserves in a filename, and the
 * Windows device names.
 */
function isSafeIdentifier(id) {
  if (typeof id !== 'string') return false;
  if (id.length === 0 || id.length > MAX_IDENTIFIER_LENGTH) return false;
  if (id.includes('\0')) return false;
  if (id === '.' || id === '..') return false;
  if (id.includes('/') || id.includes('\\')) return false;
  if (path.isAbsolute(id)) return false;
  if (/^[A-Za-z]:/.test(id)) return false;
  if (CONTROL_CHARS.test(id)) return false;
  if (WINDOWS_RESERVED_CHARS.test(id)) return false;
  if (WINDOWS_DEVICE_NAMES.test(id)) return false;
  return true;
}

/**
 * Throw `INVALID_ID` unless `id` is a safe identifier.
 * @returns {string} the id, unchanged
 */
function assertSafeIdentifier(id, label = 'identifier') {
  if (!isSafeIdentifier(id)) throw invalidIdentifier(id, label);
  return id;
}

/**
 * Resolve `filename` against `root` and refuse anything that lands outside
 * the root. `filename` is expected to be a single path segment.
 * @returns {string} the absolute, contained path
 */
function resolveWithin(root, filename, label = 'path') {
  const base = path.resolve(root);
  const full = path.resolve(base, filename);
  if (full !== base && !full.startsWith(base + path.sep)) {
    const err = new Error(`${label} escapes its root directory`);
    err.code = 'PATH_ESCAPE';
    throw err;
  }
  return full;
}

/**
 * The standard way to build a per-record file path.
 *
 * @param {string} root     the directory that must contain the file
 * @param {string} id       caller-supplied identifier
 * @param {string} suffix   e.g. '.json' or '.checkpoint.json'
 * @param {string} label    used in the error message
 * @returns {string} the absolute, contained path
 */
function recordPath(root, id, suffix, label = 'identifier') {
  assertSafeIdentifier(id, label);
  return resolveWithin(root, `${id}${suffix}`, `${label} file`);
}

module.exports = {
  isSafeIdentifier,
  assertSafeIdentifier,
  resolveWithin,
  recordPath,
  MAX_IDENTIFIER_LENGTH,
};
