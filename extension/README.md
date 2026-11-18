# PromptShield Browser Extension

> Manifest V3 Chrome/Edge/Brave extension — in-browser DLP for AI prompt inputs.

## Files

| File | Purpose |
|---|---|
| `manifest.json` | MV3 manifest — declares the `scrub-active-textarea` command (`Alt+Shift+R`), permissions, content scripts, and service worker |
| `background.js` | Service worker — receives the keyboard command from Chrome and routes it to the active tab's content script |
| `content.js` | Content script — DLP scan engine + DOM write-back + visual toast |
| `popup.html` / `popup.js` | Toolbar popup — shows the shortcut hint; "Scrub now" button for mouse users |
| `icons/` | Extension icons (16 × 16, 48 × 48, 128 × 128 PNG) |
| `tests/content.test.js` | Node ≥ 18 unit tests for the pure DLP functions — no browser needed |

## Keyboard Shortcut

| Platform | Shortcut |
|---|---|
| Windows / Linux / ChromeOS | **Alt + Shift + R** |
| macOS | **Alt (⌥) + Shift + R** |

Chrome also allows users to customise the shortcut at `chrome://extensions/shortcuts`.

## Load Unpacked (Development)

1. Open `chrome://extensions/` and enable **Developer mode**.
2. Click **Load unpacked** → select the `extension/` directory.
3. Navigate to any AI chat page and press `Alt+Shift+R` to test.

## Run Tests

```bash
node extension/tests/content.test.js
```

No dependencies required — pure Node ≥ 18.

## How It Works

```
User presses Alt+Shift+R
        │
        ▼
chrome.commands.onCommand  (background.js)
        │  chrome.tabs.sendMessage({ type: 'PROMPTSHIELD_SCRUB' })
        ▼
chrome.runtime.onMessage   (content.js)
        │  scrubActiveElement()
        ▼
 getActiveEditableElement() ──► focused <textarea> or [contenteditable]
        │  readValue()
        ▼
 scrubText(originalText)
   ├─ 60+ named DLP regex patterns
   └─ Shannon entropy fallback (H > 4.5)
        │  writeValue(el, redacted)
        ▼
 dispatchEvent('input' + 'change')   ← keeps React/Vue state in sync
        │
        ▼
 showToast(count, findings)          ← 3.5 s floating badge
```
