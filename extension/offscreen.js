// Opened briefly by the background worker, which can't touch the clipboard itself.
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type !== 'easypwd:clear-clipboard' || sender.id !== chrome.runtime.id) return undefined;
  const replace = (event) => {
    event.clipboardData.setData('text/plain', '');
    event.preventDefault();
  };
  document.addEventListener('copy', replace, { once: true });
  reply(document.execCommand('copy'));
  return undefined;
});
