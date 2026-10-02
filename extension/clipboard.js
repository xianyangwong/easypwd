// Copies text. For secrets, asks the background to clear the clipboard after the chosen delay.
export async function copyText(value, secret) {
  await navigator.clipboard.writeText(value);
  if (secret) chrome.runtime.sendMessage({ type: 'easypwd:copied' }).catch(() => {});
}
