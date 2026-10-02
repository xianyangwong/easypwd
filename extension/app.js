import {
  DEFAULT_RULES, GROUP_ORDER, MAX_BACKUP_BYTES, MAX_ENTRIES, derivePassword, encryptVault, estimateBits,
  generatePassword, normalizeIdentity, normalizeSite, parseBackup, parseOtp, sealVault, totp, unlockVault, validRules,
  validateEnvelope, validateNewMasterPassword,
} from './crypto.js';
import { entriesFromChromeCsv } from './csv.js';
import { lookup } from './lookup.js';
import { STORAGE_KEY, VaultStorage, sameVault } from './storage.js';

const $ = (id) => document.getElementById(id);
const ALL_GROUPS = GROUP_ORDER;
const GROUP_LABELS = { lowercase: 'a–z', uppercase: 'A–Z', digits: '0–9', symbols: 'symbols' };
const DEFAULT_SETTINGS = { autoLockMinutes: 5, lastBackupAt: null, generator: { length: 20, groups: ALL_GROUPS } };
const MASK = '••••••••••••';

const storage = globalThis.chrome?.storage ? new VaultStorage(chrome.storage.local, navigator.locks) : null;
let settings = structuredClone(DEFAULT_SETTINGS);
let envelope = null; // Last known stored vault.
let damaged = false;
let session = null; // { key, siteKey, identity, fingerprint, salt, entries } while unlocked.
const derived = new Map(); // Generated-password promises, keyed by settings. Cleared on lock.
let epoch = 0; // Incremented on every lock; stale async work checks it before touching state.
let busy = false;
let pending = null; // { value } of a write in flight, so our own storage events are ignored.
let lastActivity = Date.now();
let view = 'items';
let selectedId = null;
let editingId = undefined; // undefined: not editing, null: new login, string: existing login.
let revealed = false;
let lockNotice = '';

class Locked extends Error {}

// ---------- Small helpers ----------

function el(tag, props = {}, children = []) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

let toastTimer;
function toast(message, error = false) {
  const node = $('toast');
  node.textContent = message;
  node.classList.toggle('error', error);
  node.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove('show'), error ? 5000 : 2200);
}

function setIcon(button, name) {
  button.querySelector('use').setAttribute('href', `#i-${name}`);
}

function bindReveal(button, input, label) {
  button.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(show));
    button.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} ${label}`);
    setIcon(button, show ? 'eye-off' : 'eye');
  });
}

function resetReveal(button, input, label) {
  input.type = 'password';
  button.setAttribute('aria-pressed', 'false');
  button.setAttribute('aria-label', `Show ${label}`);
  setIcon(button, 'eye');
}

function hostOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

function normalizeUrl(value) {
  const text = value.trim();
  if (!text) return '';
  const candidate = /^[a-z][a-z\d+.-]*:/i.test(text) ? text : `https://${text}`;
  let url;
  try { url = new URL(candidate); } catch { url = null; }
  if (!url || !['http:', 'https:'].includes(url.protocol) || (!url.hostname.includes('.') && url.hostname !== 'localhost')) {
    throw new Error('Enter a valid web address, like example.com.');
  }
  return url.href;
}

function avatar(name, large = false) {
  let hash = 0;
  for (const character of name) hash = (hash * 31 + character.codePointAt(0)) >>> 0;
  const node = el('span', { className: `avatar${large ? ' avatar-lg' : ''}`, textContent: ([...name.trim()][0] || '?').toUpperCase() });
  node.style.background = `hsl(${hash % 360} 42% 46%)`;
  node.setAttribute('aria-hidden', 'true');
  return node;
}

function formatDate(time) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(time);
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  el('a', { href: url, download: name }).click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function readFile(file, limit) {
  if (!file) throw new Error('Choose a file.');
  if (file.size > limit) throw new Error(`The file is larger than ${Math.round(limit / 1e6)} MB.`);
  return file.text();
}

// Returns the current (or previous) password of a login, deriving it when it is generated.
function passwordFor(entry, previous = false) {
  if (!entry.derive) return Promise.resolve(entry.password);
  const spec = { ...entry.derive, counter: entry.derive.counter - (previous ? 1 : 0) };
  const id = JSON.stringify([spec.site, spec.counter, spec.length, spec.groups]);
  if (!derived.has(id)) derived.set(id, derivePassword(session.siteKey, spec));
  return derived.get(id);
}

function rulesSummary({ length, groups, counter }) {
  return `${length} characters · ${groups.map((group) => GROUP_LABELS[group]).join(', ')} · version ${counter}`;
}

function showFingerprint(keys) {
  $('fp-words').textContent = keys.fingerprint;
  $('fp-identity').textContent = keys.identity;
  $('fp-dialog').showModal();
}

// ---------- Busy state, locking, and persistence ----------

function setBusy(value) {
  busy = value;
  document.body.toggleAttribute('aria-busy', value);
  for (const button of document.querySelectorAll('button[type="submit"], #access-submit')) button.disabled = value;
}

function isActive() {
  if (!session) return false;
  if (Date.now() - lastActivity > settings.autoLockMinutes * 60_000) {
    lock(`Locked after ${settings.autoLockMinutes} minute${settings.autoLockMinutes === 1 ? '' : 's'} of inactivity.`);
    return false;
  }
  return true;
}

// Runs one action at a time. Stale results (after a lock) are discarded silently.
async function run(action, { errorEl = null, unlocked = false } = {}) {
  if (busy || (unlocked && !isActive())) return false;
  const token = epoch;
  const assertActive = () => { if (token !== epoch || (unlocked && !session)) throw new Locked(); };
  if (errorEl) errorEl.textContent = '';
  setBusy(true);
  try {
    await action(assertActive, () => token === epoch && (!unlocked || !!session));
    return true;
  } catch (error) {
    if (!(error instanceof Locked) && token === epoch) {
      if (errorEl) errorEl.textContent = error.message;
      else toast(error.message, true);
    }
    return false;
  } finally {
    if (token === epoch) setBusy(false);
  }
}

async function persist(next, canWrite) {
  const previous = envelope;
  pending = { value: next };
  try {
    await storage.replace(previous, next, canWrite);
    if (sameVault(envelope, previous)) envelope = next;
  } finally {
    pending = null;
  }
}

async function commit(entries, assertActive, canWrite) {
  const next = await encryptVault(entries, session.key, session.salt, session.identity);
  assertActive();
  await persist(next, canWrite);
  assertActive();
  session.entries = entries;
}

function lock(notice = '') {
  epoch += 1;
  session = null;
  derived.clear();
  selectedId = null;
  editingId = undefined;
  revealed = false;
  lockNotice = notice;
  setBusy(false);
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  for (const field of document.querySelectorAll('input:not([type="checkbox"]):not([type="range"]):not([type="radio"]), textarea')) {
    if (field.id !== 'gen-value') field.value = '';
  }
  $('entries').replaceChildren();
  for (const id of ['dv-password', 'dv-prev', 'dv-otp', 'entry-preview', 'set-fingerprint', 'fp-words']) $(id).textContent = '';
  stopOtpTimer();
  editorOtp = null;
  $('gen-value').value = '';
  $('app').hidden = true;
  $('lock-screen').hidden = false;
  renderLock();
}

function sessionFrom({ key, siteKey, identity, fingerprint, envelope: opened, entries }) {
  return { key, siteKey, identity, fingerprint, salt: opened.salt, entries };
}

function openSession(opened) {
  session = sessionFrom(opened);
  lastActivity = Date.now();
  lockNotice = '';
  $('master').value = '';
  $('confirm-master').value = '';
  $('ack').checked = false;
  resetReveal($('toggle-master'), $('master'), 'passphrase');
  $('lock-screen').hidden = true;
  $('app').hidden = false;
  setView('items');
  regenerate();
  $('search').focus();
  openFromHash();
}

// ---------- Lock screen ----------

function renderLock() {
  const creating = !envelope && !damaged;
  const upgrading = envelope?.version === 1 && !damaged;
  $('identity-wrap').hidden = !(creating || upgrading);
  $('lock-title').textContent = creating ? 'Create your vault' : upgrading ? 'Upgrade your vault' : 'EasyPwd';
  $('lock-subtitle').textContent = lockNotice || (creating ?
    'Remember one passphrase. EasyPwd generates a strong, unique password for every website, the same on any device.' :
    damaged ? 'The stored vault is damaged. Restore a backup or delete it.' :
    upgrading ? 'EasyPwd now generates passwords from your email and passphrase. Choose the email or name to use, then unlock.' :
    `Unlock as ${envelope.identity}`);
  $('master').placeholder = creating ? 'New master passphrase' : 'Master passphrase';
  $('master').autocomplete = creating ? 'new-password' : 'current-password';
  $('confirm-wrap').hidden = !creating;
  $('ack-wrap').hidden = !creating;
  renderLockButton();
  $('master').disabled = damaged;
  $('access-submit').disabled = damaged || busy;
  $('reset-link').hidden = creating;
  $('reset-link').textContent = damaged ? 'Delete vault' : 'Forgot passphrase?';
  $('access-error').textContent = storage ? '' : 'Open EasyPwd from its toolbar button; this page only works inside the extension.';
  if (!damaged && storage) $(!$('identity-wrap').hidden && !$('identity').value ? 'identity' : 'master').focus();
}

function updateCaps(event) {
  if (event.getModifierState) $('caps').hidden = !event.getModifierState('CapsLock');
}

$('access-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!storage || damaged) return;
  const password = $('master').value;
  const snapshot = envelope;
  let ok;
  if (!snapshot) {
    ok = await run(async (assertActive, canWrite) => {
      const identity = normalizeIdentity($('identity').value);
      validateNewMasterPassword(password);
      if (password !== $('confirm-master').value) throw new Error('The passphrases don’t match.');
      if (!$('ack').checked) throw new Error('Confirm that you understand the passphrase can’t be recovered.');
      $('access-submit').textContent = 'Creating vault…';
      const created = await sealVault([], password, identity);
      assertActive();
      await persist(created.envelope, canWrite);
      assertActive();
      openSession(created);
      showFingerprint(created);
    }, { errorEl: $('access-error') });
  } else if (snapshot.version === 1) {
    ok = await run(async (assertActive, canWrite) => {
      const identity = normalizeIdentity($('identity').value);
      $('access-submit').textContent = 'Upgrading…';
      const opened = await unlockVault(snapshot, password);
      assertActive();
      if (!sameVault(envelope, snapshot)) throw new Error('The vault changed while unlocking. Try again.');
      const sealed = await sealVault(opened.entries, password, identity);
      assertActive();
      await persist(sealed.envelope, canWrite);
      assertActive();
      openSession(sealed);
      showFingerprint(sealed);
      toast('Vault upgraded. Export a new backup.');
    }, { errorEl: $('access-error') });
  } else {
    ok = await run(async (assertActive) => {
      $('access-submit').textContent = 'Unlocking…';
      const opened = await unlockVault(snapshot, password);
      assertActive();
      if (!sameVault(envelope, snapshot)) throw new Error('The vault changed while unlocking. Try again.');
      openSession(opened);
    }, { errorEl: $('access-error') });
  }
  if (!ok && !session) {
    renderLockButton();
    $('master').focus();
    $('master').select();
  }
});

function renderLockButton() {
  $('access-submit').textContent = !envelope ? 'Create vault' : envelope.version === 1 ? 'Upgrade and unlock' : 'Unlock';
}

for (const id of ['identity', 'master', 'confirm-master']) {
  $(id).addEventListener('keydown', updateCaps);
  $(id).addEventListener('keyup', updateCaps);
  $(id).addEventListener('input', () => { if (!busy) $('access-error').textContent = ''; });
}
bindReveal($('toggle-master'), $('master'), 'passphrase');
$('restore-link').addEventListener('click', () => openRestore());
$('reset-link').addEventListener('click', () => openReset());

// ---------- Views ----------

function setView(name) {
  if (!isActive()) return;
  view = name;
  revealed = false;
  for (const page of ['items', 'generator', 'settings']) {
    $(`view-${page}`).hidden = page !== name;
    $(`nav-${page}`).toggleAttribute('aria-current', page === name);
    if (page === name) $(`nav-${page}`).setAttribute('aria-current', 'page');
  }
  if (name === 'items') renderItems();
  if (name === 'settings') renderSettings();
}

for (const page of ['items', 'generator', 'settings']) {
  $(`nav-${page}`).addEventListener('click', () => setView(page));
}
$('lock-btn').addEventListener('click', () => lock());

// ---------- Items ----------

const byName = (a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' });

function visibleEntries() {
  const query = $('search').value.trim().toLowerCase();
  return session.entries
    .filter((entry) => !query || [entry.name, entry.username, hostOf(entry.url), entry.derive?.site ?? '']
      .some((text) => text.toLowerCase().includes(query)))
    .sort(byName);
}

function renderItems() {
  if (!session) return;
  const entries = visibleEntries();
  const query = $('search').value.trim();
  $('entries').replaceChildren(...entries.map((entry) => {
    const button = el('button', { type: 'button', className: 'item' }, [
      avatar(entry.name),
      el('span', { className: 'item-text' }, [
        el('span', { className: 'item-name', textContent: entry.name }),
        el('span', { className: 'item-sub', textContent: entry.username || entry.derive?.site || hostOf(entry.url) || '—' }),
      ]),
    ]);
    if (entry.id === selectedId) button.setAttribute('aria-current', 'true');
    button.addEventListener('click', () => select(entry.id));
    return el('li', {}, [button]);
  }));
  $('list-empty').textContent = session.entries.length === 0 && !query ?
    'No logins yet. Type a website above, or click + to add one.' :
    entries.length === 0 ? `No logins match “${query}”.` : '';
  const site = normalizeSite(query);
  const suggest = entries.length === 0 && /^[^\s]+\.[a-z]{2,}$/.test(site);
  $('create-from-search').hidden = !suggest;
  $('create-from-search').textContent = suggest ? `Generate a password for ${site}` : '';
  const total = session.entries.length;
  $('item-count').textContent = total ? `${total} login${total === 1 ? '' : 's'}` : '';
  $('backup-nudge').hidden = !(total > 0 && !settings.lastBackupAt);
  renderDetail();
}

function current() {
  return session?.entries.find((entry) => entry.id === selectedId) ?? null;
}

function select(id) {
  if (!isActive()) return;
  if (editingId !== undefined) closeEditor();
  selectedId = id;
  revealed = false;
  renderItems();
}

function renderDetail() {
  const entry = current();
  const editing = editingId !== undefined;
  $('entry-form').hidden = !editing;
  $('detail-view').hidden = editing || !entry;
  $('detail-empty').hidden = editing || !!entry;
  $('view-items').classList.toggle('showing-detail', editing || !!entry);
  if (editing || !entry) {
    stopOtpTimer();
    return;
  }

  $('dv-avatar').replaceWith(Object.assign(avatar(entry.name, true), { id: 'dv-avatar' }));
  $('dv-name').textContent = entry.name;
  $('dv-host').textContent = entry.derive?.site ?? hostOf(entry.url);
  $('dv-badge').hidden = !entry.derive;
  $('dv-username-row').hidden = !entry.username;
  $('dv-username').textContent = entry.username;
  $('dv-password').textContent = revealed && !entry.derive ? entry.password : MASK;
  $('dv-reveal').setAttribute('aria-pressed', String(revealed));
  $('dv-reveal').setAttribute('aria-label', revealed ? 'Hide password' : 'Show password');
  setIcon($('dv-reveal'), revealed ? 'eye-off' : 'eye');
  const counter = entry.derive?.counter ?? 0;
  $('dv-prev-row').hidden = counter < 2;
  $('dv-prev-label').textContent = `Previous password (version ${counter - 1})`;
  $('dv-prev').textContent = MASK;
  $('dv-generated').hidden = !entry.derive;
  $('dv-rules').textContent = entry.derive ? `Generated · ${rulesSummary(entry.derive)}` : '';
  if (entry.derive && revealed) {
    const token = epoch;
    Promise.all([passwordFor(entry), counter > 1 ? passwordFor(entry, true) : '']).then(([password, previous]) => {
      if (token !== epoch || current() !== entry || !revealed || editingId !== undefined) return;
      $('dv-password').textContent = password;
      $('dv-prev').textContent = previous;
    }, () => {});
  }
  $('dv-otp-row').hidden = !entry.otp;
  if (entry.otp) startOtpTimer(entry);
  else stopOtpTimer();
  $('dv-url-row').hidden = !entry.url;
  $('dv-url').href = entry.url || '#';
  $('dv-url').textContent = entry.url.replace(/^https?:\/\//, '').replace(/\/$/, '');
  $('dv-notes-row').hidden = !entry.notes;
  $('dv-notes').textContent = entry.notes;
  $('dv-updated').textContent = entry.updatedAt ? `Last edited ${formatDate(entry.updatedAt)}` : '';

  const warnings = [];
  if (!entry.derive) {
    const reused = session.entries.filter((other) => other.id !== entry.id && !other.derive && other.password === entry.password).length;
    if (reused) warnings.push(`This password is also used for ${reused} other login${reused === 1 ? '' : 's'}.`);
    if (entry.password.length < 12) warnings.push('This password is short. Consider switching this login to a generated password.');
  }
  $('dv-warnings').replaceChildren(...warnings.map((text) => el('li', {}, [warnIcon(), text])));
}

// ---------- Two-factor codes ----------

let otpTimer = null;
let otpEntry = null;

const formatCode = (code) => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code);

function stopOtpTimer() {
  clearInterval(otpTimer);
  otpTimer = null;
  otpEntry = null;
}

function startOtpTimer(entry) {
  if (otpEntry === entry && otpTimer) return;
  stopOtpTimer();
  otpEntry = entry;
  const token = epoch;
  const tick = async () => {
    if (token !== epoch || current() !== entry || editingId !== undefined) return stopOtpTimer();
    const { code, remaining, period } = await totp(entry.otp);
    if (token !== epoch || current() !== entry) return;
    $('dv-otp').textContent = formatCode(code);
    $('dv-otp-timer').style.setProperty('--p', String(remaining / period));
    $('dv-otp-timer').classList.toggle('low', remaining <= 5);
    $('dv-otp-timer').title = `${remaining}s left`;
  };
  $('dv-otp').textContent = '';
  tick().catch(() => {});
  otpTimer = setInterval(() => { tick().catch(() => {}); }, 1000);
}

function warnIcon() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'icon icon-sm');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#i-warn');
  svg.append(use);
  return svg;
}

$('search').addEventListener('input', renderItems);
$('search').addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  const entries = visibleEntries();
  if (!$('create-from-search').hidden) $('create-from-search').click();
  else if (entries.length === 1) select(entries[0].id);
});
$('dv-reveal').addEventListener('click', () => {
  if (!isActive()) return;
  revealed = !revealed;
  renderDetail();
});
$('detail-back').addEventListener('click', () => { selectedId = null; renderItems(); });

for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const entry = current();
    if (!entry || !isActive()) return;
    const field = button.dataset.copy;
    const labels = { username: 'Username', password: 'Password', previous: 'Previous password', url: 'Website', otp: '2FA code' };
    try {
      const value = field === 'otp' ? (await totp(entry.otp)).code :
        field === 'password' || field === 'previous' ? await passwordFor(entry, field === 'previous') : entry[field];
      await navigator.clipboard.writeText(value);
      toast(`${labels[field]} copied`);
    } catch {
      toast('Couldn’t access the clipboard. Click the page and try again.', true);
    }
  });
}

$('create-from-search').addEventListener('click', () => {
  if (!isActive()) return;
  const site = normalizeSite($('search').value);
  selectedId = null;
  openEditor(null, site);
});

$('dv-rotate').addEventListener('click', async () => {
  const entry = current();
  if (!entry?.derive || !isActive()) return;
  const next = entry.derive.counter + 1;
  if (!await confirmAction(`New password for “${entry.name}”?`,
    `EasyPwd will switch to version ${next}. Change your password on ${entry.derive.site} to the new one. ` +
    'The previous password stays here until you rotate again.', 'Generate new password', false)) return;
  await run(async (assertActive, canWrite) => {
    const entries = session.entries.map((item) => (item.id === entry.id ?
      { ...item, derive: { ...item.derive, counter: next }, updatedAt: Date.now() } : item));
    await commit(entries, assertActive, canWrite);
    revealed = true;
    renderItems();
    toast('New password ready. Update it on the website.');
  }, { unlocked: true });
});

$('dv-delete').addEventListener('click', async () => {
  const entry = current();
  if (!entry || !isActive()) return;
  if (!await confirmAction(`Delete “${entry.name}”?`, 'This login will be removed from your vault. This can’t be undone unless you have a backup.', 'Delete')) return;
  await run(async (assertActive, canWrite) => {
    await commit(session.entries.filter((item) => item.id !== entry.id), assertActive, canWrite);
    selectedId = null;
    renderItems();
    toast('Login deleted');
  }, { unlocked: true });
});

// ---------- Editor ----------

let editorOriginal = null; // Generation settings of the login being edited.
let editorOtp = null; // Two-factor settings matching the 2FA field, so non-default digits/periods survive edits.
let previewToken = 0;

const editorMode = () => document.querySelector('input[name="entry-mode"]:checked').value;
const sameSpec = (a, b) => JSON.stringify([a.site, a.counter, a.length, a.groups]) === JSON.stringify([b.site, b.counter, b.length, b.groups]);

function editorSpec() {
  return {
    site: normalizeSite($('entry-site').value),
    counter: Number($('entry-counter').value),
    length: Number($('entry-length').value),
    groups: GROUP_ORDER.filter((group) => document.querySelector(`input[name="entry-group"][value="${group}"]`).checked),
  };
}

function specError({ site, counter, length, groups }) {
  if (!site) return 'Enter the website this password is for.';
  if (!validRules(length, groups)) return 'Choose a length from 8 to 64 and at least one character group.';
  if (!Number.isSafeInteger(counter) || counter < 1 || counter > 1_000_000) return 'Version must be a whole number from 1 to 1,000,000.';
  return '';
}

async function updatePreview() {
  const token = ++previewToken;
  const generated = editorMode() === 'generated';
  const spec = editorSpec();
  $('entry-derive-warn').hidden = !(generated && editorOriginal && !sameSpec(spec, editorOriginal));
  if (!generated || !session) return;
  const error = specError(spec);
  let text = error === 'Enter the website this password is for.' ? 'Type a website to see its password.' : error;
  if (!error) {
    try { text = await passwordFor({ derive: spec }); } catch (failure) { text = failure.message; }
  }
  if (token !== previewToken || !session) return;
  $('entry-preview').textContent = text;
  $('entry-preview').classList.toggle('placeholder', !!error);
}

function renderMode() {
  const generated = editorMode() === 'generated';
  $('gen-fields').hidden = !generated;
  $('gen-fields-2').hidden = !generated;
  $('saved-fields').hidden = generated;
  $('mode-hint').textContent = generated ?
    'Calculated from your master passphrase and the website. Nothing to store, and the same on every device.' :
    'Stored encrypted in this vault. Use it for passwords you can’t change, like existing accounts or Wi‑Fi.';
  $('entry-name').placeholder = generated ? 'Optional. Defaults to the website' : 'e.g. GitHub';
  updatePreview();
}

function setMode(mode) {
  for (const input of document.querySelectorAll('input[name="entry-mode"]')) input.checked = input.value === mode;
  renderMode();
}

function openEditor(id, site = '') {
  if (!isActive()) return;
  const entry = id ? session.entries.find((item) => item.id === id) : null;
  editingId = entry ? entry.id : null;
  editorOriginal = entry?.derive ?? null;
  const spec = entry?.derive ?? { site, counter: 1, ...DEFAULT_RULES };
  $('form-title').textContent = entry ? 'Edit login' : 'New login';
  $('entry-site').value = spec.site;
  $('entry-length').value = String(spec.length);
  $('entry-counter').value = String(spec.counter);
  for (const input of document.querySelectorAll('input[name="entry-group"]')) input.checked = spec.groups.includes(input.value);
  $('entry-name').value = entry?.name ?? '';
  $('entry-username').value = entry?.username ?? '';
  $('entry-password').value = entry?.password ?? '';
  $('entry-url').value = entry?.url ?? '';
  $('entry-notes').value = entry?.notes ?? '';
  editorOtp = entry?.otp ?? null;
  $('entry-otp').value = editorOtp?.secret ?? '';
  $('form-error').textContent = '';
  resetReveal($('toggle-entry-password'), $('entry-password'), 'password');
  resetReveal($('toggle-entry-otp'), $('entry-otp'), 'setup key');
  setMode(entry && !entry.derive ? 'saved' : 'generated');
  renderDetail();
  $(entry || site ? 'entry-name' : 'entry-site').focus();
}

function closeEditor() {
  editingId = undefined;
  editorOriginal = null;
  editorOtp = null;
  previewToken += 1;
  for (const id of ['entry-site', 'entry-name', 'entry-username', 'entry-password', 'entry-url', 'entry-notes', 'entry-otp']) $(id).value = '';
  $('entry-preview').textContent = '';
  renderDetail();
}

$('new-entry').addEventListener('click', () => {
  selectedId = null;
  renderItems();
  openEditor(null);
});
$('dv-edit').addEventListener('click', () => openEditor(selectedId));
$('cancel-edit').addEventListener('click', closeEditor);
$('form-back').addEventListener('click', closeEditor);
bindReveal($('toggle-entry-password'), $('entry-password'), 'password');
$('fill-generated').addEventListener('click', () => {
  if (!isActive()) return;
  const { length, groups } = settings.generator;
  $('entry-password').value = generatePassword(length, groups);
  if ($('entry-password').type === 'password') $('toggle-entry-password').click();
});

for (const input of document.querySelectorAll('input[name="entry-mode"]')) {
  input.addEventListener('change', async () => {
    const preview = $('entry-preview');
    // Carry values across so switching modes never loses the password the user is looking at.
    if (editorMode() === 'saved') {
      if (!$('entry-password').value && preview.textContent && !preview.classList.contains('placeholder')) {
        $('entry-password').value = preview.textContent;
      }
      if (!$('entry-url').value && $('entry-site').value) {
        try { $('entry-url').value = normalizeUrl($('entry-site').value); } catch { /* not a web address */ }
      }
    } else if (!$('entry-site').value && $('entry-url').value) {
      $('entry-site').value = normalizeSite($('entry-url').value);
    }
    renderMode();
  });
}
for (const id of ['entry-site', 'entry-length', 'entry-counter']) $(id).addEventListener('input', updatePreview);
for (const input of document.querySelectorAll('input[name="entry-group"]')) {
  input.addEventListener('change', () => {
    if (!document.querySelector('input[name="entry-group"]:checked')) input.checked = true;
    updatePreview();
  });
}
$('preview-copy').addEventListener('click', async () => {
  const preview = $('entry-preview');
  if (!isActive() || !preview.textContent || preview.classList.contains('placeholder')) return;
  try {
    await navigator.clipboard.writeText(preview.textContent);
    toast('Password copied');
  } catch {
    toast('Couldn’t access the clipboard. Click the page and try again.', true);
  }
});

// Turns an otpauth:// link into its setup key, and fills in the name and username from it.
function applyOtpInput(text) {
  const { otp, issuer, account } = parseOtp(text);
  editorOtp = otp;
  $('entry-otp').value = otp.secret;
  if (issuer && !$('entry-name').value.trim()) $('entry-name').value = issuer;
  if (account && !$('entry-username').value.trim()) $('entry-username').value = account;
  $('form-error').textContent = '';
}

function editorOtpValue() {
  const value = $('entry-otp').value.trim();
  if (!value) return null;
  if (editorOtp && value === editorOtp.secret) return editorOtp;
  return parseOtp(value).otp;
}

bindReveal($('toggle-entry-otp'), $('entry-otp'), 'setup key');
$('entry-otp').addEventListener('change', () => {
  if (!/^otpauth:/i.test($('entry-otp').value.trim())) return;
  try { applyOtpInput($('entry-otp').value); } catch (error) { $('form-error').textContent = error.message; }
});

async function scanQr(blob) {
  if (!isActive()) return;
  try {
    const detector = new BarcodeDetector({ formats: ['qr_code'] });
    const image = await createImageBitmap(blob);
    const codes = await detector.detect(image);
    image.close();
    const link = codes.map((code) => code.rawValue).find((value) => /^otpauth:/i.test(value));
    if (!link) throw new Error('No two-factor QR code found in that image.');
    if (editingId === undefined) return;
    applyOtpInput(link);
    toast('2FA added from QR code');
  } catch (error) {
    $('form-error').textContent = error.message || 'Couldn’t read that image.';
  }
}

if ('BarcodeDetector' in globalThis) {
  $('entry-otp-scan').hidden = false;
  $('entry-otp-scan').addEventListener('click', () => $('entry-otp-file').click());
  $('entry-otp-file').addEventListener('change', () => {
    const [file] = $('entry-otp-file').files;
    $('entry-otp-file').value = '';
    if (file) scanQr(file);
  });
  $('entry-form').addEventListener('paste', (event) => {
    const file = [...event.clipboardData.files].find((item) => item.type.startsWith('image/'));
    if (!file) return;
    event.preventDefault();
    scanQr(file);
  });
} else {
  $('entry-otp-hint').textContent = 'Optional. On the website’s two-factor setup page, choose “can’t scan?” and paste the key here.';
}

$('entry-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = editingId;
  await run(async (assertActive, canWrite) => {
    const generated = editorMode() === 'generated';
    const spec = editorSpec();
    const otp = editorOtpValue();
    let entry;
    if (generated) {
      const error = specError(spec);
      if (error) throw new Error(error);
      let url = '';
      try { url = spec.site.includes('.') ? normalizeUrl(spec.site) : ''; } catch { /* free-text site */ }
      entry = {
        id: id ?? crypto.randomUUID(),
        name: $('entry-name').value.trim() || spec.site,
        url,
        username: $('entry-username').value.trim(),
        password: '',
        notes: $('entry-notes').value,
        updatedAt: Date.now(),
        derive: spec,
      };
    } else {
      const name = $('entry-name').value.trim();
      if (!name) throw new Error('Give this login a name.');
      if (!$('entry-password').value) throw new Error('Enter a password, or click Random.');
      entry = {
        id: id ?? crypto.randomUUID(),
        name,
        url: normalizeUrl($('entry-url').value),
        username: $('entry-username').value.trim(),
        password: $('entry-password').value,
        notes: $('entry-notes').value,
        updatedAt: Date.now(),
      };
    }
    if (otp) entry.otp = otp;
    if (id === null && session.entries.length >= MAX_ENTRIES) throw new Error(`A vault can hold up to ${MAX_ENTRIES} logins.`);
    const entries = id === null ? [...session.entries, entry] : session.entries.map((item) => (item.id === id ? entry : item));
    await commit(entries, assertActive, canWrite);
    selectedId = entry.id;
    revealed = false;
    $('search').value = '';
    closeEditor();
    renderItems();
    toast(id === null ? 'Login saved' : 'Changes saved');
  }, { unlocked: true, errorEl: $('form-error') });
});

// ---------- Generator ----------

function selectedGroups() {
  return [...document.querySelectorAll('input[name="gen-group"]:checked')].map((input) => input.value);
}

function regenerate() {
  const length = Number($('gen-length').value);
  const groups = selectedGroups();
  $('gen-length-value').textContent = String(length);
  $('gen-value').value = generatePassword(length, groups);
  const bits = estimateBits(length, groups);
  const strength = bits >= 100 ? 'Very strong' : bits >= 75 ? 'Strong' : bits >= 55 ? 'Fair' : 'Weak';
  $('gen-bits').textContent = `${strength} · about ${bits} bits of entropy`;
}

function saveGenerator() {
  settings.generator = { length: Number($('gen-length').value), groups: selectedGroups() };
  saveSettings();
}

$('gen-length').addEventListener('input', regenerate);
$('gen-length').addEventListener('change', saveGenerator);
for (const input of document.querySelectorAll('input[name="gen-group"]')) {
  input.addEventListener('change', () => {
    if (!selectedGroups().length) input.checked = true;
    regenerate();
    saveGenerator();
  });
}
$('gen-refresh').addEventListener('click', regenerate);
$('gen-copy').addEventListener('click', async () => {
  if (!isActive()) return;
  try {
    await navigator.clipboard.writeText($('gen-value').value);
    toast('Password copied');
  } catch {
    toast('Couldn’t access the clipboard. Click the page and try again.', true);
  }
});

// ---------- Settings ----------

async function saveSettings() {
  if (storage) await chrome.storage.local.set({ settings });
}

function applySettings(value) {
  const stored = value && typeof value === 'object' ? value : {};
  const generator = stored.generator ?? {};
  const groups = Array.isArray(generator.groups) ? generator.groups.filter((group) => ALL_GROUPS.includes(group)) : [];
  settings = {
    autoLockMinutes: [1, 5, 15, 30].includes(stored.autoLockMinutes) ? stored.autoLockMinutes : DEFAULT_SETTINGS.autoLockMinutes,
    lastBackupAt: Number.isSafeInteger(stored.lastBackupAt) ? stored.lastBackupAt : null,
    generator: {
      length: Number.isInteger(generator.length) && generator.length >= 8 && generator.length <= 64 ? generator.length : 20,
      groups: groups.length ? [...new Set(groups)] : ALL_GROUPS,
    },
  };
  $('gen-length').value = String(settings.generator.length);
  for (const input of document.querySelectorAll('input[name="gen-group"]')) {
    input.checked = settings.generator.groups.includes(input.value);
  }
  renderSettings();
}

function renderSettings() {
  $('autolock').value = String(settings.autoLockMinutes);
  $('last-backup').textContent = settings.lastBackupAt ?
    `Last exported ${formatDate(settings.lastBackupAt)}.` :
    'Not exported yet. Keep a backup somewhere other than this browser.';
  $('set-identity').textContent = session?.identity ?? '';
  $('set-fingerprint').textContent = session?.fingerprint ?? '';
  if (session && view === 'items') $('backup-nudge').hidden = !(session.entries.length > 0 && !settings.lastBackupAt);
}

$('autolock').addEventListener('change', () => {
  if (!isActive()) return;
  settings.autoLockMinutes = Number($('autolock').value);
  saveSettings();
  toast('Auto-lock updated');
});

function exportBackup() {
  if (!isActive() || !envelope) return;
  const { format, version, identity, kdf, salt, iv, ciphertext } = envelope;
  const backup = {
    format, version, ...(version === 2 ? { identity } : {}),
    kdf: { name: kdf.name, hash: kdf.hash, iterations: kdf.iterations }, salt, iv, ciphertext,
  };
  download(`easypwd-backup-${new Date().toISOString().slice(0, 10)}.json`, `${JSON.stringify(backup, null, 2)}\n`);
  settings.lastBackupAt = Date.now();
  saveSettings();
  renderSettings();
  toast('Encrypted backup exported');
}
$('export').addEventListener('click', exportBackup);
$('backup-nudge').addEventListener('click', exportBackup);

$('open-import').addEventListener('click', () => { if (isActive()) $('import-file').click(); });
$('import-file').addEventListener('change', async () => {
  const file = $('import-file').files[0];
  $('import-file').value = '';
  if (!file) return;
  await run(async (assertActive, canWrite) => {
    const { entries, skipped } = entriesFromChromeCsv(await readFile(file, 5_000_000));
    assertActive();
    const key = (entry) => `${entry.url}\n${entry.username}\n${entry.password}`;
    const existing = new Set(session.entries.map(key));
    const fresh = entries.filter((entry) => !existing.has(key(entry)) && existing.add(key(entry)));
    if (session.entries.length + fresh.length > MAX_ENTRIES) throw new Error(`A vault can hold up to ${MAX_ENTRIES} logins.`);
    if (fresh.length) await commit([...session.entries, ...fresh], assertActive, canWrite);
    const duplicates = entries.length - fresh.length;
    const notes = [duplicates && `${duplicates} already in your vault`, skipped && `${skipped} invalid`].filter(Boolean).join(', ');
    toast(`Imported ${fresh.length} login${fresh.length === 1 ? '' : 's'}${notes ? ` · skipped ${notes}` : ''}. Delete the CSV file now.`);
  }, { unlocked: true });
});

// ---------- Dialogs ----------

function confirmAction(title, body, label, danger = true) {
  const dialog = $('confirm-dialog');
  $('confirm-title').textContent = title;
  $('confirm-body').textContent = body;
  $('confirm-ok').textContent = label;
  $('confirm-ok').classList.toggle('danger-fill', danger);
  dialog.returnValue = '';
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), { once: true });
  });
}

for (const button of document.querySelectorAll('[data-close]')) {
  button.addEventListener('click', () => button.closest('dialog').close());
}

function openRestore() {
  if (session && !isActive()) return;
  $('restore-file').value = '';
  $('restore-pass').value = '';
  $('restore-identity').value = '';
  $('restore-identity-wrap').hidden = true;
  $('restore-error').textContent = '';
  $('restore-body').textContent = envelope ?
    'This replaces the vault stored in this browser. Logins that aren’t in the backup will be lost.' :
    'Choose an EasyPwd backup file and enter the master passphrase it was created with.';
  $('restore-dialog').showModal();
}
$('open-restore').addEventListener('click', openRestore);

$('restore-file').addEventListener('change', async () => {
  let version = 2;
  try { version = parseBackup(await readFile($('restore-file').files[0], MAX_BACKUP_BYTES)).version; } catch { /* reported on submit */ }
  $('restore-identity-wrap').hidden = version !== 1;
});

$('restore-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = $('restore-file').files[0];
  const password = $('restore-pass').value;
  await run(async (assertActive, canWrite) => {
    const backup = parseBackup(await readFile(file, MAX_BACKUP_BYTES));
    const identity = backup.version === 1 ? normalizeIdentity($('restore-identity').value) : null;
    let opened = await unlockVault(backup, password).catch(() => {
      throw new Error('That passphrase doesn’t open this backup.');
    });
    assertActive();
    if (identity) opened = await sealVault(opened.entries, password, identity);
    assertActive();
    await persist(opened.envelope, canWrite);
    assertActive();
    damaged = false;
    $('restore-dialog').close();
    openSession(opened);
    if (identity) showFingerprint(opened);
    toast(`Restored ${opened.entries.length} login${opened.entries.length === 1 ? '' : 's'}`);
  }, { errorEl: $('restore-error') });
});

$('open-change-pass').addEventListener('click', () => {
  if (!isActive()) return;
  for (const id of ['cp-current', 'cp-new', 'cp-confirm']) $(id).value = '';
  $('cp-error').textContent = '';
  const count = session.entries.filter((entry) => entry.derive).length;
  $('cp-note').hidden = !count;
  $('cp-note').textContent = `Every generated password depends on your passphrase. ${count} generated login${count === 1 ? '' : 's'} will be kept as saved passwords so ${count === 1 ? 'it keeps' : 'they keep'} working.`;
  $('pass-dialog').showModal();
});

$('pass-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  await run(async (assertActive, canWrite) => {
    const next = $('cp-new').value;
    validateNewMasterPassword(next);
    if (next !== $('cp-confirm').value) throw new Error('The new passphrases don’t match.');
    await unlockVault(envelope, $('cp-current').value).catch(() => {
      throw new Error('The current passphrase is incorrect.');
    });
    assertActive();
    const entries = await Promise.all(session.entries.map(async (entry) => {
      if (!entry.derive) return entry;
      const { derive, ...saved } = entry;
      return { ...saved, password: await passwordFor(entry) };
    }));
    assertActive();
    const sealed = await sealVault(entries, next, session.identity);
    assertActive();
    await persist(sealed.envelope, canWrite);
    assertActive();
    session = sessionFrom(sealed);
    derived.clear();
    $('pass-dialog').close();
    renderItems();
    renderSettings();
    showFingerprint(sealed);
    toast('Master passphrase changed. Export a new backup.');
  }, { unlocked: true, errorEl: $('cp-error') });
});

function openReset() {
  if (session && !isActive()) return;
  $('reset-confirm').value = '';
  $('reset-error').textContent = '';
  $('reset-dialog').showModal();
  $('reset-confirm').focus();
}
$('open-reset').addEventListener('click', openReset);

$('reset-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if ($('reset-confirm').value.trim() !== 'DELETE') {
    $('reset-error').textContent = 'Type DELETE to confirm.';
    return;
  }
  await run(async (assertActive, canWrite) => {
    await persist(null, canWrite);
    assertActive();
    damaged = false;
    settings.lastBackupAt = null;
    await saveSettings();
    lock();
    toast('Vault deleted');
  }, { errorEl: $('reset-error') });
});

// ---------- Activity, keyboard, and cross-tab changes ----------

for (const type of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
  document.addEventListener(type, (event) => {
    if (!event.isTrusted) return;
    if (session && isActive()) lastActivity = Date.now();
  }, { capture: true, passive: true });
}
setInterval(isActive, 15_000);
document.addEventListener('visibilitychange', isActive);
window.addEventListener('focus', isActive);

document.addEventListener('keydown', (event) => {
  if (!session || document.querySelector('dialog[open]')) return;
  const typing = event.target.closest('input, textarea, select');
  if (event.key === '/' && !typing && view === 'items') {
    event.preventDefault();
    $('search').focus();
  } else if (event.key === 'Escape' && editingId !== undefined) {
    closeEditor();
  }
});

if (storage) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.settings) applySettings(changes.settings.newValue);
    if (!changes[STORAGE_KEY]) return;
    const next = changes[STORAGE_KEY].newValue ?? null;
    if ((pending && sameVault(pending.value, next)) || sameVault(envelope, next)) return;
    envelope = next;
    damaged = false;
    try { if (next) validateEnvelope(next); } catch { damaged = true; }
    if (session) lock('The vault was changed in another tab. Unlock to continue.');
    else if (!busy) renderLock();
  });
}

// ---------- Toolbar popup ----------

// The popup opens vault.html#new=<site> to save a login for the page the user is on.
function openFromHash() {
  const match = /^#new=(.*)$/.exec(location.hash);
  if (!match || !isActive()) return;
  history.replaceState(null, '', location.pathname);
  let site = '';
  try { site = normalizeSite(decodeURIComponent(match[1])).slice(0, 1_024); } catch { /* ignore */ }
  setView('items');
  selectedId = null;
  $('search').value = '';
  renderItems();
  openEditor(null, site);
}
window.addEventListener('hashchange', openFromHash);

// Answers the popup with matching logins while this tab is unlocked.
// A locked tab stays silent, so the popup asks for the passphrase itself.
if (globalThis.chrome?.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (message?.type !== 'easypwd:lookup' || sender.id !== chrome.runtime.id || sender.tab ||
        !sender.url?.startsWith(chrome.runtime.getURL('popup.html')) ||
        typeof message.host !== 'string' || typeof message.site !== 'string' || !session || !isActive()) return undefined;
    lastActivity = Date.now();
    const token = epoch;
    lookup(session, message).then(
      (result) => reply(token === epoch && session ? result : null),
      () => reply(null),
    );
    return true;
  });
}

// ---------- Start ----------

async function start() {
  if (!storage) {
    renderLock();
    $('master').disabled = true;
    $('access-submit').disabled = true;
    return;
  }
  const stored = await chrome.storage.local.get(['settings', STORAGE_KEY]);
  applySettings(stored.settings);
  envelope = stored[STORAGE_KEY] ?? null;
  try { if (envelope) validateEnvelope(envelope); } catch { damaged = true; }
  renderLock();
}

start().catch((error) => {
  $('access-error').textContent = `EasyPwd couldn’t start: ${error.message}`;
});
