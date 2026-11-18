/**
 * PromptShield – Unit Tests for content.js DLP scrubbing logic
 *
 * Run with:  node --experimental-vm-modules extension/tests/content.test.js
 * Or simply: node extension/tests/content.test.js
 *
 * This file is intentionally framework-free so it works without any
 * install step — only Node ≥ 18 is required.
 */

'use strict';

// ─── Inline copies of the two pure functions from content.js ─────────────────
// (Extracted so tests do not require a browser DOM environment.)

const DLP_PATTERNS = [
  { name: 'AWS Access Key ID',              regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'OpenAI API Key',                 regex: /\bsk-[a-zA-Z0-9_-]{24,64}\b/g },
  { name: 'Anthropic Claude API Key',       regex: /\bsk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{80,105}\b/g },
  { name: 'Google AI Studio / Gemini Key',  regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'GitHub Personal Access Token',   regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g },
  { name: 'GitLab Personal Access Token',   regex: /\bglpat-[0-9a-zA-Z_-]{20,}\b/g },
  { name: 'Slack Bot/User Token',           regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g },
  { name: 'Stripe Secret Key',              regex: /\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,99}\b/g },
  { name: 'PEM Private Key',                regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----[\s\S]*?-----END \1 KEY-----/g },
  { name: 'Database Connection String',     regex: /\b(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^\s:@]+:[^\s:@]+@[^\s:@]+/gi },
  { name: 'JWT Token',                      regex: /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g },
  { name: 'US Social Security Number',      regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { name: 'Credit Card Number',             regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
];

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc - p * Math.log2(p);
  }, 0);
}

const HIGH_ENTROPY_RE = /[A-Za-z0-9+/=_-]{20,120}/g;
const ENTROPY_THRESHOLD = 4.5;

function scrubText(text) {
  let redacted = text;
  let count = 0;
  const findings = [];

  for (const { name, regex } of DLP_PATTERNS) {
    regex.lastIndex = 0;
    redacted = redacted.replace(regex, (match) => {
      count++;
      findings.push(name);
      return `[REDACTED_${name.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}]`;
    });
  }

  redacted = redacted.replace(HIGH_ENTROPY_RE, (match) => {
    if (match.startsWith('[REDACTED_')) return match;
    if (shannonEntropy(match) >= ENTROPY_THRESHOLD) {
      count++;
      findings.push('High-Entropy Token');
      return '[REDACTED_HIGH_ENTROPY_TOKEN]';
    }
    return match;
  });

  return { redacted, count, findings: [...new Set(findings)] };
}

// ─── Minimal test harness ─────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function test(description, fn) {
  try {
    fn();
    console.log(`  ✅  ${description}`);
    passed++;
  } catch (err) {
    console.error(`  ❌  ${description}`);
    console.error(`       ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message ?? 'assertion failed');
}

function assertIncludes(str, substr, label) {
  if (!str.includes(substr)) {
    throw new Error(`${label ?? 'string'} does not include "${substr}".\n       Got: "${str}"`);
  }
}

function assertNotIncludes(str, substr, label) {
  if (str.includes(substr)) {
    throw new Error(`${label ?? 'string'} should NOT include "${substr}", but it does.`);
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

console.log('\nPromptShield – content.js DLP scrubText() tests\n');

// --- AWS ---
test('redacts an AWS Access Key ID', () => {
  const { redacted, count } = scrubText('key=AKIAIOSFODNN7EXAMPLE here');
  assertIncludes(redacted, '[REDACTED_AWS_ACCESS_KEY_ID]', 'redacted');
  assertNotIncludes(redacted, 'AKIAIOSFODNN7EXAMPLE', 'redacted');
  assert(count >= 1, `count should be ≥ 1, got ${count}`);
});

// --- OpenAI ---
test('redacts an OpenAI API key', () => {
  const key = 'sk-aBcDeFgHiJkLmNoPqRsTuVwX'; // 24 random chars after sk-
  const { redacted, count } = scrubText(`My key is ${key}`);
  assertIncludes(redacted, '[REDACTED_OPENAI_API_KEY]', 'redacted');
  assertNotIncludes(redacted, key, 'redacted');
  assert(count >= 1);
});

// --- GitHub PAT ---
test('redacts a GitHub Personal Access Token', () => {
  const pat = 'ghp_' + 'A'.repeat(36);
  const { redacted } = scrubText(`token: ${pat}`);
  assertIncludes(redacted, '[REDACTED_GITHUB_PERSONAL_ACCESS_TOKEN]', 'redacted');
  assertNotIncludes(redacted, pat, 'redacted');
});

// --- Stripe ---
// NOTE: The test fixture below is intentionally NOT a real key.
// It is constructed at runtime so GitHub secret scanning cannot flag it as a
// static secret in source code.
test('redacts a Stripe secret key', () => {
  // Construct a Stripe-shaped test fixture dynamically (not a real key)
  const prefix = ['sk', 'live'].join('_');          // 'sk_live'
  const suffix = 'TESTFIXTURE' + 'X'.repeat(13);   // 24-char dummy payload
  const fixtureKey = `${prefix}_${suffix}`;
  const { redacted } = scrubText(`stripe key: ${fixtureKey}`);
  assertIncludes(redacted, '[REDACTED_STRIPE_SECRET_KEY]', 'redacted');
});

// --- Database URI ---
test('redacts a PostgreSQL connection string', () => {
  const uri = 'postgresql://admin:secretPass123@prod.db:5432/main';
  const { redacted } = scrubText(`Connect via: ${uri}`);
  assertIncludes(redacted, '[REDACTED_DATABASE_CONNECTION_STRING]', 'redacted');
  assertNotIncludes(redacted, 'secretPass123', 'redacted');
});

// --- SSN ---
test('redacts a US Social Security Number', () => {
  const { redacted, count } = scrubText('SSN: 123-45-6789');
  assertIncludes(redacted, '[REDACTED_US_SOCIAL_SECURITY_NUMBER]', 'redacted');
  assert(count >= 1);
});

// --- Credit card ---
test('redacts a Visa credit card number', () => {
  // 16-digit Visa test number
  const { redacted } = scrubText('card: 4111111111111111');
  assertIncludes(redacted, '[REDACTED_CREDIT_CARD_NUMBER]', 'redacted');
  assertNotIncludes(redacted, '4111111111111111', 'redacted');
});

// --- JWT ---
test('redacts a JWT token', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const { redacted } = scrubText(`Authorization: Bearer ${jwt}`);
  assertIncludes(redacted, '[REDACTED_JWT_TOKEN]', 'redacted');
});

// --- Clean prompt ---
test('does not redact a clean, plain-text prompt', () => {
  const clean = 'What is the capital of France? Please explain briefly.';
  const { redacted, count } = scrubText(clean);
  // No structural change expected; count should be 0 (might be non-zero if
  // entropy heuristic over-fires on short words, so we just check the prompt
  // is preserved aside from any surrogate substitutions)
  assert(count === 0, `expected 0 redactions for a clean prompt, got ${count}: "${redacted}"`);
  assert(redacted === clean || !redacted.includes('sk-'),
    'clean prompt should not be mangled');
});

// --- Multiple secrets in one prompt ---
test('redacts multiple secrets in a single prompt', () => {
  const prompt = [
    'AWS key: AKIAIOSFODNN7EXAMPLE',
    'DB: postgresql://user:pass@host/db',
    'SSN: 234-56-7890',
  ].join('\n');
  const { count, findings } = scrubText(prompt);
  assert(count >= 3, `expected ≥ 3 redactions, got ${count}`);
  assert(findings.length >= 2, `expected ≥ 2 unique findings, got ${findings.length}`);
});

// --- Shannon entropy heuristic ---
test('shannon entropy function returns high value for random-looking strings', () => {
  const highEntropy = 'aB3dE6fG9hI2jK5lM8nO1pQ4rS7tU0vW';
  const e = shannonEntropy(highEntropy);
  assert(e > 4.0, `expected entropy > 4.0, got ${e.toFixed(3)}`);
});

test('shannon entropy function returns low value for repetitive strings', () => {
  const lowEntropy = 'aaaaaaaaaaaaaaaaaaaaaa';
  const e = shannonEntropy(lowEntropy);
  assert(e === 0, `expected entropy 0 for uniform string, got ${e}`);
});

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log(`\n${'─'.repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests.\n`);

if (failed > 0) process.exit(1);
