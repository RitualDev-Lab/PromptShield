/**
 * PromptShield – Popup Script
 *
 * Wires the "Scrub Active Textarea Now" button in popup.html.
 * Sends a PROMPTSHIELD_SCRUB message to the content script running in the
 * currently active tab, mirroring what the keyboard shortcut does.
 */

'use strict';

document.getElementById('scrub-btn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'PROMPTSHIELD_SCRUB' });
  } catch {
    // Content script not yet present – inject it first, then fire the message.
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files:  ['content.js'],
      });
      setTimeout(async () => {
        try {
          await chrome.tabs.sendMessage(tab.id, { type: 'PROMPTSHIELD_SCRUB' });
        } catch { /* non-scriptable page */ }
      }, 50);
    } catch { /* scripting permission denied */ }
  }

  // Close the popup after triggering
  window.close();
});
