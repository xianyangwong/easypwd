import { normalizeSite, unlockVault, validateEnvelope } from './crypto.js';
import { guessSite, lookup } from './lookup.js';
import { openVault } from './open-vault.js';
import { STORAGE_KEY } from './storage.js';

const $ = (id) => document.getElementById(id);
const MASK = '••••••••••••';

let tab = null;
let host = '';
let site = '';
let local = null; // { entries, siteKey } when unlocked in this popup. Gone when the popup closes.
let result = null;
let suggestRevealed = false;
let refreshing = false;

function el(tag, props = {}, children = []) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'icon');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

function iconButton(name, label, onClick) {
  const button = el('button', { type: 'button', className: 'icon-btn', title: label, onclick: onClick }, [icon(name)]);
  button.setAttribute('aria-label', label);
  return button;
}

function status(message, bad = false) {
  $('status').textContent = message;
  $('status').classList.toggle('bad', bad);
}

function show(...ids) {
  for (const id of ['no-site', 'setup', 'unlock', 'results']) $(id).hidden = !ids.includes(id);
}

const formatCode = (code) => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code);

async function copy(value, label) {
  try {
    await navigator.clipboard.writeText(value);
    status(`${label} copied`);
  } catch {
    status('Couldn’t access the clipboard.', true);
  }
}

// ---------- Filling the page ----------

// Runs inside the web page. Fills the visible login form and reports what it found.
function fillLogin(username, password) {
  const visible = (input) => !input.disabled && !input.readOnly && input.getClientRects().length > 0 &&
    getComputedStyle(input).visibility !== 'hidden';
  const set = (input, value) => {
    input.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll('input')].filter(visible);
  const textLike = (input) => ['text', 'email', 'tel'].includes(input.type);
  const passwords = inputs.filter((input) => input.type === 'password');
  const filled = { username: false, password: false };
  if (passwords.length) {
    const first = passwords[0];
    const form = first.form;
    // A sign-up form gets the password in its "confirm" field too; a login form has only one.
    const current = passwords.filter((input) => input.autocomplete === 'current-password');
    const targets = current.length ? current : passwords.filter((input) => input.form === form);
    for (const input of targets) set(input, password);
    filled.password = true;
    if (username) {
      const before = inputs.filter((input) => textLike(input) && input.form === form &&
        (input.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING));
      const field = before.findLast((input) => /user|email|login|account|name/i.test(`${input.autocomplete} ${input.name} ${input.id}`)) ?? before.at(-1);
      if (field) { set(field, username); filled.username = true; }
    }
    first.focus();
  } else if (username) {
    // Two-step logins ask for the username first.
    const field = inputs.find((input) => textLike(input) && /username|email/.test(input.autocomplete)) ??
      inputs.find((input) => textLike(input) && (input.type === 'email' || /user|email|login|account/i.test(`${input.name} ${input.id}`)));
    if (field) { set(field, username); filled.username = true; }
  }
  return filled;
}

// Runs inside the web page. Fills a one-time-code field, including one-box-per-digit layouts.
function fillCode(code) {
  const visible = (input) => !input.disabled && !input.readOnly && input.getClientRects().length > 0;
  const set = (input, value) => {
    input.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll('input')].filter((input) => visible(input) && ['text', 'tel', 'number', 'password'].includes(input.type));
  const boxes = inputs.filter((input) => input.maxLength === 1);
  if (boxes.length >= code.length) {
    boxes.slice(0, code.length).forEach((input, index) => set(input, code[index]));
    return true;
  }
  const field = inputs.find((input) => input.autocomplete === 'one-time-code') ??
    inputs.find((input) => input.type !== 'password' && /otp|code|totp|2fa|mfa|token|verif|pin/i.test(`${input.name} ${input.id} ${input.placeholder} ${input.getAttribute('aria-label') ?? ''}`));
  if (!field) return false;
  set(field, code);
  return true;
}

async function inject(func, args) {
  // Only fill the page the popup was opened for.
  const now = await chrome.tabs.get(tab.id);
  if (normalizeSite(new URL(now.url).hostname) !== host) throw new Error('The page changed. Open EasyPwd again.');
  const [frame] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func, args });
  return frame?.result;
}

async function fillMatch(match) {
  try {
    const filled = await inject(fillLogin, [match.username, match.password]);
    if (filled?.password || filled?.username) {
      window.close();
      return;
    }
    await copy(match.password, 'No login form found. Password');
  } catch (error) {
    status(error.message, true);
  }
}

async function fillOtp(code) {
  try {
    if (await inject(fillCode, [code])) {
      window.close();
      return;
    }
    await copy(code, 'No code field found. 2FA code');
  } catch (error) {
    status(error.message, true);
  }
}

// ---------- Results ----------

function renderMatch(match) {
  const name = el('div', { className: 'match-name' }, [el('strong', { textContent: match.name })]);
  if (match.username) name.append(el('span', { textContent: match.username }));
  const head = el('div', { className: 'match-head' }, [
    name,
    ...(match.username ? [iconButton('user', 'Copy username', () => copy(match.username, 'Username'))] : []),
    iconButton('key', 'Copy password', () => copy(match.password, 'Password')),
    el('button', { type: 'button', className: 'btn primary', textContent: 'Fill', onclick: () => fillMatch(match) }),
  ]);
  const item = el('li', { className: 'match' }, [head]);
  if (match.otp) {
    const code = el('span', { className: 'mono', textContent: formatCode(match.otp.code) });
    const timer = el('span', { className: 'otp-timer' });
    timer.dataset.expires = String(match.otp.expiresAt);
    timer.dataset.period = String(match.otp.period);
    item.append(el('div', { className: 'otp' }, [
      el('span', { className: 'otp-label', textContent: '2FA' }),
      code,
      timer,
      iconButton('copy', 'Copy 2FA code', () => copy(match.otp.code, '2FA code')),
      el('button', { type: 'button', className: 'btn', textContent: 'Fill code', onclick: () => fillOtp(match.otp.code) }),
    ]));
  }
  return item;
}

function renderSuggestion() {
  const password = result?.suggestion?.password ?? '';
  $('suggest-password').textContent = suggestRevealed ? password : (password ? MASK : '—');
  $('suggest-reveal').setAttribute('aria-pressed', String(suggestRevealed));
  $('suggest-reveal').setAttribute('aria-label', suggestRevealed ? 'Hide password' : 'Show password');
  $('suggest-reveal').querySelector('use').setAttribute('href', suggestRevealed ? '#i-eye-off' : '#i-eye');
  for (const id of ['suggest-fill', 'suggest-copy', 'suggest-save']) $(id).disabled = !password;
}

function render() {
  const now = Date.now();
  for (const match of result.matches) {
    if (match.otp) match.otp.expiresAt = now + match.otp.remaining * 1000;
  }
  $('matches').replaceChildren(...result.matches.map(renderMatch));
  const none = result.matches.length === 0;
  $('suggest').hidden = !none;
  $('add-login').hidden = none;
  if (none && document.activeElement !== $('suggest-site')) $('suggest-site').value = result.suggestion?.site ?? site;
  renderSuggestion();
  show('results');
  tickOtp();
}

function tickOtp() {
  let expired = false;
  for (const timer of document.querySelectorAll('.otp-timer')) {
    const remaining = Math.ceil((Number(timer.dataset.expires) - Date.now()) / 1000);
    if (remaining <= 0) expired = true;
    timer.style.setProperty('--p', String(Math.max(remaining, 0) / Number(timer.dataset.period)));
    timer.classList.toggle('low', remaining <= 5);
    timer.title = `${Math.max(remaining, 0)}s left`;
  }
  if (expired) refresh();
}

// ---------- Vault access ----------

async function query() {
  if (local) return lookup(local, { host, site });
  try {
    // An unlocked vault tab answers; locked or closed ones don't.
    return (await chrome.runtime.sendMessage({ type: 'easypwd:lookup', host, site })) ?? null;
  } catch {
    return null;
  }
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const next = await query();
    if (next) {
      result = next;
      render();
      return;
    }
    if (local) throw new Error('Lookup failed.');
    const stored = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
    if (!stored) {
      show('setup');
      return;
    }
    validateEnvelope(stored);
    if (stored.version === 1) {
      $('no-site-text').textContent = 'Open the vault once to upgrade it, then try again.';
      show('no-site');
      return;
    }
    $('unlock-identity').textContent = `For ${stored.identity}`;
    show('unlock');
    $('unlock-pass').focus();
  } catch (error) {
    status(error.message, true);
  } finally {
    refreshing = false;
  }
}

$('unlock').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('unlock-pass').value;
  $('unlock-error').textContent = '';
  $('unlock-submit').disabled = true;
  $('unlock-submit').textContent = 'Unlocking…';
  try {
    const stored = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
    const opened = await unlockVault(stored, password);
    if (!opened.siteKey) throw new Error('Open the vault once to upgrade it, then try again.');
    local = { entries: opened.entries, siteKey: opened.siteKey };
    $('unlock-pass').value = '';
    await refresh();
  } catch (error) {
    $('unlock-error').textContent = error.message;
    $('unlock-pass').select();
  } finally {
    $('unlock-submit').disabled = false;
    $('unlock-submit').textContent = 'Unlock';
  }
});

// ---------- Suggestion ----------

let suggestTimer;
$('suggest-site').addEventListener('input', () => {
  clearTimeout(suggestTimer);
  suggestTimer = setTimeout(() => {
    site = normalizeSite($('suggest-site').value) || guessSite(host);
    refresh();
  }, 250);
});
$('suggest-reveal').addEventListener('click', () => {
  suggestRevealed = !suggestRevealed;
  renderSuggestion();
});
$('suggest-copy').addEventListener('click', () => copy(result.suggestion.password, 'Password'));
$('suggest-fill').addEventListener('click', () => fillMatch({ username: '', password: result.suggestion.password }));

function openAndClose(hash) {
  openVault(hash).then(() => window.close(), (error) => status(error.message, true));
}
$('suggest-save').addEventListener('click', () => openAndClose(`#new=${encodeURIComponent(result.suggestion.site)}`));
$('add-login').addEventListener('click', () => openAndClose(`#new=${encodeURIComponent(guessSite(host))}`));
$('open-vault').addEventListener('click', () => openAndClose(''));
$('setup-open').addEventListener('click', () => openAndClose(''));

// ---------- Start ----------

async function start() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url = null;
  try { url = new URL(tab?.url); } catch { /* not a web page */ }
  if (!url || !/^https?:$/.test(url.protocol) || !url.hostname) {
    show('no-site');
    return;
  }
  host = normalizeSite(url.hostname);
  site = guessSite(host);
  $('site-host').textContent = host;
  $('site-insecure').hidden = url.protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  $('site').hidden = false;
  await refresh();
  setInterval(tickOtp, 1000);
}

start().catch((error) => status(`EasyPwd couldn’t start: ${error.message}`, true));
