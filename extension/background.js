async function openVault() {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  const url = chrome.runtime.getURL('vault.html');
  const tabs = await chrome.tabs.query({});
  const existing = tabs.find((tab) => tab.url === url);
  if (existing) {
    await chrome.tabs.update(existing.id, { active: true });
    await chrome.windows.update(existing.windowId, { focused: true });
  } else {
    await chrome.tabs.create({ url });
  }
}

chrome.action.onClicked.addListener(() => {
  openVault().catch((error) => console.error('EasyPwd could not open the vault.', error));
});
