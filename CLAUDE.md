# PromptShield

> In-browser AI Data Loss Prevention (DLP) and Prompt Firewall extension (Manifest V3) preventing secret, credential & PII leaks into ChatGPT, Claude, and Gemini.

## Architecture
- **In-Memory DFA & Regex Scanner**: Evaluates prompt text streams across 40+ high-entropy credential signatures and 15+ PII patterns.
- **Shannon Entropy Engine**: Flags high-entropy pseudo-random strings resembling API tokens and private keys even when pattern prefixes are obscured.
- **Manifest V3 Content Script**: Attaches non-intrusively to LLM chat input fields (ChatGPT, Claude, Gemini, DeepSeek) and intercepts outbound form submission/fetch requests.

## Commands
- Run CLI: `npx @ritualdev/promptshield --help`
- Live Playground: https://ritualdev.in/promptshield
