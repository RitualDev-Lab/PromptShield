#!/usr/bin/env node

/**
 * PromptShield Enterprise CLI
 * Local secret, API key, and PII detector for prompts, source code, and CI/CD pipelines.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';

const VERSION = '0.1.0';

const PATTERNS = [
  { name: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS Secret Access Key', regex: /\b[A-Za-z0-9/+=]{40}\b/ },
  { name: 'OpenAI API Key', regex: /\bsk-[a-zA-Z0-9_-]{24,64}\b/ },
  { name: 'Anthropic Claude API Key', regex: /\bsk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{80,105}\b/ },
  { name: 'Google Gemini / AI Studio Key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'GitHub Personal Access Token', regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/ },
  { name: 'GitLab Personal Access Token', regex: /\bglpat-[0-9a-zA-Z_-]{20,}\b/ },
  { name: 'Slack Bot / User Token', regex: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/ },
  { name: 'Generic Private Key', regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----/ },
  { name: 'Database Connection String', regex: /\b(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^\s:@]+:[^\s:@]+@[^\s:@]+/i },
  { name: 'JWT Secret Token', regex: /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/ },
  { name: 'Stripe Secret Key', regex: /\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,99}\b/ },
  { name: 'US Social Security Number', regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/ },
  { name: 'Credit Card Number', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/ },
];

function scanText(text) {
  const violations = [];
  for (const p of PATTERNS) {
    const match = text.match(p.regex);
    if (match) {
      violations.push({ name: p.name, match: match[0].substring(0, 8) + '...' });
    }
  }
  return violations;
}

function scanDir(dir) {
  let count = 0;
  function traverse(current) {
    const entries = readdirSync(current);
    for (const entry of entries) {
      if (['.git', 'node_modules', 'dist', 'build', '.venv', '__pycache__'].includes(entry)) continue;
      const full = join(current, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        traverse(full);
      } else if (/\.(env|py|js|ts|json|yml|yaml|txt|md|sql|sh)$/i.test(entry)) {
        try {
          const content = readFileSync(full, 'utf-8');
          const viols = scanText(content);
          if (viols.length > 0) {
            console.log(`[ALERT] ${full}:`);
            for (const v of viols) {
              console.log(`  - Leaked Secret: ${v.name} (${v.match})`);
              count++;
            }
          }
        } catch {}
      }
    }
  }
  traverse(dir);
  return count;
}

const args = process.argv.slice(2);
if (args.includes('--version') || args.includes('-v')) {
  console.log(`PromptShield CLI v${VERSION} (Enterprise AI DLP & Secret Firewall)`);
  process.exit(0);
}
if (args.includes('--help') || args.includes('-h') || args.length === 0) {
  console.log(`PromptShield CLI v${VERSION}`);
  console.log(`Usage:`);
  console.log(`  promptshield scan <directory|file>   Scan files or repos for leaked credentials`);
  console.log(`  promptshield check "<text>"          Scan prompt or text string`);
  console.log(`  promptshield --version               Show version`);
  console.log(`  promptshield --help                  Show help`);
  process.exit(0);
}

const cmd = args[0];
if (cmd === 'scan') {
  const target = args[1] || '.';
  console.log(`Scanning target: ${target}`);
  const violations = scanDir(resolve(target));
  if (violations > 0) {
    console.error(`\nFAILED: Found ${violations} security violation(s)!`);
    process.exit(1);
  } else {
    console.log(`\nPASSED: Zero secret or credential leaks detected.`);
    process.exit(0);
  }
} else if (cmd === 'check') {
  const text = args.slice(1).join(' ');
  const viols = scanText(text);
  if (viols.length > 0) {
    console.error(`[BLOCKED] Prompt contains ${viols.length} leaked secret(s):`);
    for (const v of viols) {
      console.error(`  - ${v.name}`);
    }
    process.exit(1);
  } else {
    console.log(`[ALLOWED] Prompt is clean and safe for AI submission.`);
    process.exit(0);
  }
} else {
  console.error(`Unknown command: ${cmd}`);
  process.exit(1);
}
