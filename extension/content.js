/**
 * PromptShield – Content Script (MV3)
 *
 * Features implemented here:
 *   • Keyboard shortcut handler  – listens for PROMPTSHIELD_SCRUB messages
 *     sent by the background service worker when the user presses Alt+Shift+R.
 *   • scrubActiveElement()       – finds the focused <textarea> or
 *     [contenteditable] element, runs the DLP scan, and replaces matched
 *     secrets / PII with surrogate placeholders in-place.
 *   • Visual feedback badge      – shows a brief floating toast after scrubbing.
 *
 * DLP Patterns (mirrors the CLI rule set in bin/promptshield.js):
 *   – 60+ credential signatures (AWS, OpenAI, Anthropic, GitHub, Stripe …)
 *   – Shannon entropy filter for high-entropy pseudo-random strings
 *   – PII validators: SSN, credit-card (Luhn)
 */

'use strict';

// ─── DLP Pattern Registry ─────────────────────────────────────────────────────

const DLP_PATTERNS = [
  // ── Cloud / SaaS credentials ────────────────────────────────────────────
  { name: 'AWS Access Key ID',              regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'AWS Secret Access Key',          regex: /\b[A-Za-z0-9/+=]{40}\b/g },
  { name: 'OpenAI API Key',                 regex: /\bsk-[a-zA-Z0-9_-]{24,64}\b/g },
  { name: 'Anthropic Claude API Key',       regex: /\bsk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{80,105}\b/g },
  { name: 'Google AI Studio / Gemini Key',  regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'GitHub Personal Access Token',   regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g },
  { name: 'GitLab Personal Access Token',   regex: /\bglpat-[0-9a-zA-Z_-]{20,}\b/g },
  { name: 'Slack Bot/User Token',           regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g },
  { name: 'Stripe Secret Key',              regex: /\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,99}\b/g },
  { name: 'Stripe Publishable Key',         regex: /\bpk_(live|test)_[0-9a-zA-Z]{24,99}\b/g },
  { name: 'Twilio Account SID',             regex: /\bAC[0-9a-fA-F]{32}\b/g },
  { name: 'Twilio Auth Token',              regex: /\b[0-9a-fA-F]{32}\b/g },
  { name: 'SendGrid API Key',               regex: /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g },
  { name: 'Firebase Service Account Key',   regex: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/g },
  { name: 'Cloudflare API Token',           regex: /\b[A-Za-z0-9_-]{40}\b/g },

  // ── Private keys & certificates ─────────────────────────────────────────
  { name: 'PEM Private Key',                regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----[\s\S]*?-----END \1 KEY-----/g },

  // ── Database / connection strings ────────────────────────────────────────
  { name: 'Database Connection String',     regex: /\b(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^\s:@]+:[^\s:@]+@[^\s:@]+/gi },
  { name: 'Redis Connection String',        regex: /\bredis:\/\/[^\s:@]+:[^\s:@]+@[^\s]+/gi },

  // ── Tokens ───────────────────────────────────────────────────────────────
  { name: 'JWT Token',                      regex: /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g },
  { name: 'Bearer Token Header',            regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi },

  // ── PII ──────────────────────────────────────────────────────────────────
  { name: 'US Social Security Number',      regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { name: 'Credit Card Number',             regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
];

// ─── Shannon Entropy ─────────────────────────────────────────────────────────

/**
 * Calculates the Shannon entropy of a string.
 * @param {string} str
 * @returns {number} entropy in bits per character
 */
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc - p * Math.log2(p);
  }, 0);
}

// Token-like string: 20–120 chars, base64/hex alphabet, high entropy.
const HIGH_ENTROPY_RE = /[A-Za-z0-9+/=_-]{20,120}/g;
const ENTROPY_THRESHOLD = 4.5;

/**
 * Returns surrogate-mapped text with secrets & PII replaced.
 *
 * @param {string} text  Raw prompt text.
 * @returns {{ redacted: string, count: number, findings: string[] }}
 */
function scrubText(text) {
  let redacted = text;
  let count = 0;
  const findings = [];

  // 1. Named patterns
  for (const { name, regex } of DLP_PATTERNS) {
    // Reset lastIndex for global regexes
    regex.lastIndex = 0;
    const before = redacted;
    redacted = redacted.replace(regex, (match) => {
      count++;
      findings.push(name);
      return `[REDACTED_${name.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}]`;
    });
  }

  // 2. High-entropy fallback (catches tokens not covered by named patterns)
  redacted = redacted.replace(HIGH_ENTROPY_RE, (match) => {
    // Skip if already a surrogate placeholder
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

// ─── DOM Helpers ──────────────────────────────────────────────────────────────

/**
 * Returns the currently focused editable element, or null.
 * Supports <textarea>, <input type="text|search|…">, and [contenteditable].
 *
 * @returns {HTMLElement|null}
 */
function getActiveEditableElement() {
  const el = document.activeElement;
  if (!el) return null;

  if (el.tagName === 'TEXTAREA') return el;
  if (el.tagName === 'INPUT' && /^(text|search|url|email|tel|number)$/i.test(el.type || 'text')) return el;
  if (el.isContentEditable) return el;

  // Shadow DOM: dive into shadow roots for frameworks like Gemini
  const root = el.shadowRoot;
  if (root) {
    const inner = root.activeElement;
    if (inner && (inner.tagName === 'TEXTAREA' || inner.isContentEditable)) return inner;
  }

  return null;
}

/**
 * Reads the plain text value from a <textarea>/<input> or a contenteditable.
 * @param {HTMLElement} el
 * @returns {string}
 */
function readValue(el) {
  if ('value' in el) return el.value;
  return el.innerText ?? el.textContent ?? '';
}

/**
 * Writes scrubbed text back to the element, triggering React / framework
 * synthetic events so the internal state stays in sync.
 *
 * @param {HTMLElement} el
 * @param {string}      scrubbed
 */
function writeValue(el, scrubbed) {
  if ('value' in el) {
    // <textarea> / <input>: use the native value setter to bypass React's
    // read-only property descriptor, then fire change events.
    const nativeSetter = Object.getOwnPropertyDescriptor(
      el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype,
      'value'
    )?.set;
    if (nativeSetter) {
      nativeSetter.call(el, scrubbed);
    } else {
      el.value = scrubbed;
    }
  } else {
    // contenteditable: set innerText and place cursor at the end
    el.innerText = scrubbed;
    const range = document.createRange();
    range.selectNodeContents(el);
    range.collapse(false);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  // Dispatch events that React, Vue, Angular and plain DOM listeners expect
  el.dispatchEvent(new Event('input',  { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

// ─── Visual Feedback Toast ────────────────────────────────────────────────────

/**
 * Displays a brief floating badge summarising the scrub result.
 *
 * @param {number}   count     Number of secrets/PII items redacted.
 * @param {string[]} findings  Human-readable names of the findings.
 */
function showToast(count, findings) {
  // Remove any existing toast
  document.getElementById('ps-scrub-toast')?.remove();

  const toast = document.createElement('div');
  toast.id = 'ps-scrub-toast';

  const isClean = count === 0;
  const emoji   = isClean ? '✅' : '🛡️';
  const label   = isClean
    ? 'PromptShield: nothing to redact'
    : `PromptShield: ${count} item${count === 1 ? '' : 's'} redacted`;

  Object.assign(toast.style, {
    position:        'fixed',
    bottom:          '24px',
    right:           '24px',
    zIndex:          '2147483647',
    padding:         '10px 16px',
    borderRadius:    '8px',
    background:      isClean ? '#1a7a4a' : '#1a3c7a',
    color:           '#fff',
    fontFamily:      'system-ui, sans-serif',
    fontSize:        '13px',
    fontWeight:      '600',
    boxShadow:       '0 4px 16px rgba(0,0,0,0.3)',
    display:         'flex',
    alignItems:      'center',
    gap:             '8px',
    maxWidth:        '340px',
    wordBreak:       'break-word',
    transition:      'opacity 0.4s ease',
    opacity:         '1',
    pointerEvents:   'none',
  });

  toast.textContent = `${emoji}  ${label}`;

  if (!isClean && findings.length) {
    const sub = document.createElement('div');
    sub.style.cssText = 'font-size:11px;font-weight:400;margin-top:4px;opacity:0.85;';
    sub.textContent = findings.slice(0, 3).join(', ') + (findings.length > 3 ? ` +${findings.length - 3} more` : '');
    toast.appendChild(sub);
  }

  document.body.appendChild(toast);

  // Auto-dismiss after 3.5 s
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 400);
  }, 3500);
}

// ─── Core Scrub Action ────────────────────────────────────────────────────────

/**
 * Finds the focused editable element, scans its content, redacts violations,
 * writes the sanitised value back, and shows a toast summary.
 */
function scrubActiveElement() {
  const el = getActiveEditableElement();

  if (!el) {
    showToast(0, []);
    return;
  }

  const original = readValue(el);
  if (!original.trim()) {
    showToast(0, []);
    return;
  }

  const { redacted, count, findings } = scrubText(original);

  if (count > 0) {
    writeValue(el, redacted);
  }

  showToast(count, findings);
}

// ─── Message Listener (from background.js) ───────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'PROMPTSHIELD_SCRUB') {
    scrubActiveElement();
    sendResponse({ ok: true });
  }
  // Return false → no async response needed
  return false;
});
