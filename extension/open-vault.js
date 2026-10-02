// Focuses the vault tab, or opens one. `hash` (e.g. "#new=github.com") asks it to start a new login.
export async function openVault(hash = '') {
  const base = chrome.runtime.getURL('vault.html');
  // getContexts sees the extension's own tabs without the "tabs" permission.
  const contexts = await chrome.runtime.getContexts({ contextTypes: ['TAB'] });
  const existing = contexts.find((context) => context.documentUrl?.split('#')[0] === base);
  if (existing) {
    await chrome.windows.update(existing.windowId, { focused: true });
    await chrome.tabs.update(existing.tabId, { active: true, ...(hash ? { url: base + hash } : {}) });
  } else {
    await chrome.tabs.create({ url: base + hash });
  }
}
