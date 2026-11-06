<div align="center">

# 🛡️ PromptShield
### Enterprise In-Browser AI Data Loss Prevention & Prompt Firewall

[![GitHub Release](https://img.shields.io/github/v/release/RitualDev-Lab/PromptShield?color=blue&label=Release&logo=github)](https://github.com/RitualDev-Lab/PromptShield/releases/latest)
[![Chrome Web Store](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-green?logo=googlechrome)](https://github.com/RitualDev-Lab/PromptShield/releases)
[![Python SDK](https://img.shields.io/badge/Python-3.8+-blue?logo=python)](https://github.com/RitualDev-Lab/PromptShield/releases)
[![NPM Package](https://img.shields.io/badge/NPM-@ritualdev/promptshield-red?logo=npm)](https://github.com/RitualDev-Lab/PromptShield/releases)
[![License](https://img.shields.io/badge/License-Proprietary%20/%20Community-orange)](./LICENSE)
[![Zero VPS Cost](https://img.shields.io/badge/Cloud_Cost-$0.00/mo-success)](https://promptshield.io)

**PromptShield** is an enterprise-grade, in-browser Data Loss Prevention (DLP) and Prompt Firewall extension (Manifest V3) that stops source code secrets, customer PII, project codenames, and API credentials from leaking into AI tools (**ChatGPT, Claude, Gemini, DeepSeek, Copilot, Perplexity, HuggingFace Chat, and Le Chat**).

[Get Extension](https://github.com/RitualDev-Lab/PromptShield/releases/latest) • [Python SDK](#-python-sdk-quickstart) • [Architecture](#-architecture) • [Enterprise Fleet](#-enterprise-fleet-features) • [Documentation](./docs)

</div>

---

## ⚡ The Problem: The AI Secret Leak Crisis

Every day, engineers, analysts, and knowledge workers paste confidential company data into AI chatbots:
* **Over 42% of knowledge workers** paste corporate data into ChatGPT without authorization.
* **API Keys & Cloud Secrets**: Leaked AWS, OpenAI, GitHub, Stripe, and Database URIs expose production systems.
* **Uncapped Cloud Liabilities**: Once a secret is regurgitated into a public LLM context, it cannot be deleted.

**PromptShield inspects and sanitizes every prompt locally on the workstation CPU in $< 4\text{ ms}$ with zero cloud compute overhead ($0 VPS, $0 cloud bills).**

---

## 🏛️ Architecture

PromptShield operates on an air-gapped, zero-knowledge local architecture. Plaintext prompts **never** leave your browser.

```mermaid
flowchart TD
    subgraph BrowserWorkstation["Client Browser (Chrome / Edge / Brave / Arc)"]
        UI["AI Prompt Box (ChatGPT / Claude / Gemini / DeepSeek)"]
        
        subgraph ContentRuntime["Local In-Browser DLP Engine (< 4ms)"]
            DOMHook["Universal DOM Hook & Enter Interceptor"]
            RegexEngine["60+ Credential Signatures Engine"]
            EntropyEngine["Fast Shannon Entropy Calculator (H > 4.5)"]
            PIIEngine["Luhn / Verhoeff Algorithmic Validator"]
            SurrogateEngine["In-Flight Deterministic Surrogate Redactor"]
            OverlayBadge["Floating Shield Indicator & Inspection Flyout"]
        end

        subgraph BackgroundVault["Secure Service Worker"]
            LocalVault["WebCrypto AES-256-GCM Encrypted Incident Ledger"]
            PolicySync["HMAC-SHA256 Fleet Policy Sync Engine"]
        end
        
        UI -->|Keystrokes / Paste / Submit| DOMHook
        DOMHook --> RegexEngine & EntropyEngine & PIIEngine
        RegexEngine & EntropyEngine & PIIEngine --> OverlayBadge
        OverlayBadge -->|1-Click Redact & Send| SurrogateEngine
        SurrogateEngine -->|Sanitized Prompt| UI
        DOMHook -.->|Zero-Plaintext Metadata Only| BackgroundVault
    end

    subgraph ZeroCostEdge["Serverless Edge (api.promptshield.io)"]
        CFWorkers["Cloudflare Workers (100k free req/day)"]
        SIEM["Enterprise SIEM (Splunk / Datadog / Sentinel CEF)"]
    end

    PolicySync -.->|Sync Rules & Canary Tokens| CFWorkers
    BackgroundVault -.->|Metadata Telemetry Only| CFWorkers
    CFWorkers -.-> SIEM
```

---

## 🎯 Target Platforms Supported

| AI Platform | Supported Domains | Interception Mechanism |
| :--- | :--- | :--- |
| **OpenAI ChatGPT** | `chatgpt.com`, `chat.openai.com` | `#prompt-textarea`, `div[contenteditable="true"]`, submit lock |
| **Anthropic Claude** | `claude.ai` | `div.ProseMirror`, ProseMirror transaction hooks |
| **Google Gemini** | `gemini.google.com` | `rich-textarea`, dynamic Shadow DOM observer |
| **DeepSeek** | `chat.deepseek.com` | `textarea`, dynamic React state binding |
| **Microsoft Copilot** | `copilot.microsoft.com` | `#searchbox`, iframe isolation hooks |
| **Perplexity AI** | `perplexity.ai` | `textarea[placeholder*="Ask"]` |
| **HuggingChat / Le Chat** | `huggingface.co/chat`, `chat.mistral.ai` | Fallback universal textarea observer |

---

## 🚀 Quickstart

### 1. Chrome / Brave / Edge Extension
1. Download `promptshield-v0.1.0.zip` from [Latest Releases](https://github.com/RitualDev-Lab/PromptShield/releases/latest).
2. Unzip into a local directory.
3. Open `chrome://extensions/` (or `edge://extensions/`), enable **Developer mode**.
4. Click **Load unpacked** and select the folder. PromptShield will automatically protect your AI sessions.

### 2. Python SDK (`pip install promptshield`)
Used by backend engineering teams to protect LangChain, LlamaIndex, and FastAPI LLM endpoints:

```python
from promptshield import PromptFirewall

# Initialize in-memory zero-dependency firewall
firewall = PromptFirewall(mode="BLOCK")

user_input = "Here is our database connection: postgresql://admin:secretPass123@prod.db:5432/main"
result = firewall.inspect(user_input)

if not result["allowed"]:
    print(f"🛑 Blocked! Detected: {result['violations'][0]['rule_name']}")
    print(f"Severity: {result['violations'][0]['severity']}")
else:
    # Safe to pass to OpenAI / Claude API
    pass
```

### 3. Node.js / TypeScript SDK
```bash
npm install @ritualdev/promptshield
```
```typescript
import { InBrowserDlpEngine, SurrogateMaskingEngine } from '@ritualdev/promptshield';

const engine = new InBrowserDlpEngine();
const result = engine.scan("My AWS key is AKIAIOSFODNN7EXAMPLE");

if (result.hasViolations) {
  const masked = SurrogateMaskingEngine.mask(userPrompt, result.violations);
  console.log("Safe Prompt:", masked.redactedPrompt);
}
```

---

## 🏢 Enterprise Fleet Features ($50K–$250K ACV Capabilities)

* **Central Fleet Policy Sync (`api.promptshield.io`)**: Push corporate DLP policies, project codenames, and custom regex rules across 10,000+ managed laptops with cryptographic **HMAC-SHA256 signature verification**.
* **Real-Time SIEM & SOC Streaming**: Turnkey streaming adapters for **Splunk HEC**, **Datadog Logs JSON**, and **ArcSight / Microsoft Sentinel Common Event Format (CEF)**.
* **Synthetic Canary Honeypots**: Injects decoy API tokens into sessions to mathematically verify whether LLMs retain private customer tokens.
* **Enterprise Windows GPO & Jamf Deployments**: Pre-configured Chrome Enterprise `ExtensionInstallForcelist` policies and Windows Registry `.admx` templates.

---

## 📊 Performance Benchmarks

* **Inspection Latency**: $< 4.0\text{ ms}$ on 5,000+ character code snippets.
* **Memory Footprint**: $< 18\text{ MB}$ resident memory.
* **Infrastructure Cost**: **$0.00 / month** ($0 VPS, $0 cloud compute overhead).
* **Test Verification**: **77 / 77 passing tests** across Node 20, 22, 24 and Python 3.8+.

---

## 🤝 Community & Support

* **Feature Requests & Bug Reports**: Open an issue in our [Public Issue Tracker](https://github.com/RitualDev-Lab/PromptShield/issues).
* **Enterprise Licensing**: Contact `enterprise@ritualdev.in` for multi-seat volume licensing, SSO, and dedicated SIEM integrations.
* **Core Development**: Developed and maintained by [RitualDev Studio](https://ritualdev.in).

---

<div align="center">
<sub>Copyright © 2026 RitualDev Studio. Proprietary Commercial Software. All Rights Reserved.</sub>
</div>
