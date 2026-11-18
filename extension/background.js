/**
 * PromptShield – Background Service Worker (MV3)
 *
 * Responsibilities:
 *   1. Listen for the `scrub-active-textarea` keyboard command (Alt+Shift+R).
 *   2. Forward the command to the active tab's content script.
 *   3. Fall back to chrome.scripting.executeScript when the content script is
 *      not yet injected (e.g. on a plain http page not in content_scripts.matches).
 */

'use strict';

// ─── Command routing ─────────────────────────────────────────────────────────

chrome.commands.onCommand.addListener(async (command) => {
  if (command !== 'scrub-active-textarea') return;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  // Try messaging the already-injected content script first.
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'PROMPTSHIELD_SCRUB' });
  } catch {
    // Content script not present (e.g. chrome:// or new-tab page) – inject on
    // the fly using the scripting API and then fire the scrub.
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files:  ['content.js'],
      });
      // Give the script a tick to initialise before sending the message.
      setTimeout(async () => {
        try {
          await chrome.tabs.sendMessage(tab.id, { type: 'PROMPTSHIELD_SCRUB' });
        } catch { /* non-scriptable page – silently ignore */ }
      }, 50);
    } catch { /* scripting permission denied – silently ignore */ }
  }
});
