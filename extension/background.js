// Keep the encrypted vault out of reach of content scripts (EasyPwd injects only a one-off fill function).
async function protectStorage() {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}

chrome.runtime.onInstalled.addListener(() => { protectStorage().catch(console.error); });
chrome.runtime.onStartup.addListener(() => { protectStorage().catch(console.error); });

// ---------- Clipboard clearing ----------

const CLEAR_ALARM = 'easypwd:clear-clipboard';
const CLEAR_DELAYS = [0, 30, 60, 120];

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type !== 'easypwd:copied' || sender.id !== chrome.runtime.id ||
      !sender.url?.startsWith(chrome.runtime.getURL(''))) return undefined;
  scheduleClear().catch(console.error);
  return undefined;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CLEAR_ALARM) clearClipboard().catch(console.error);
});

async function scheduleClear() {
  const seconds = (await chrome.storage.local.get('settings')).settings?.clearClipboardSeconds ?? 30;
  if (!CLEAR_DELAYS.includes(seconds) || seconds === 0) return chrome.alarms.clear(CLEAR_ALARM);
  return chrome.alarms.create(CLEAR_ALARM, { when: Date.now() + seconds * 1000 });
}

async function clearClipboard() {
  const url = chrome.runtime.getURL('offscreen.html');
  const open = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'], documentUrls: [url] });
  if (!open.length) {
    await chrome.offscreen.createDocument({
      url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Clear a copied password from the clipboard.',
    });
  }
  try {
    await chrome.runtime.sendMessage({ type: 'easypwd:clear-clipboard' });
  } finally {
    await chrome.offscreen.closeDocument();
  }
}
