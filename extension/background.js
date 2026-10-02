// Keep the encrypted vault out of reach of content scripts (EasyPwd injects only a one-off fill function).
async function protectStorage() {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}

chrome.runtime.onInstalled.addListener(() => { protectStorage().catch(console.error); });
chrome.runtime.onStartup.addListener(() => { protectStorage().catch(console.error); });
