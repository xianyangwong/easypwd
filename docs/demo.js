import { deriveKeys, derivePassword, normalizeSite, estimateBits, GROUPS } from './crypto.js';
import { scramble } from './motion.js';

const $ = (id) => document.getElementById(id);
const SALT = 'AAAAAAAAAAAAAAAAAAAAAA==';
const form = $('demo');
let keyCache = { id: '', key: null };
let run = 0;
let counter = 1;
let shown = { fp: '', pw: '' };

const groups = () => [...$('d-groups').querySelectorAll('input:checked')].map((box) => box.value);
const charClass = (c) => GROUPS.lowercase.includes(c) ? 'g-lower'
  : GROUPS.uppercase.includes(c) ? 'g-upper' : GROUPS.digits.includes(c) ? 'g-digit' : 'g-symbol';

function colorize(el, text) {
  el.replaceChildren(...[...text].map((c) => {
    const span = document.createElement('span');
    span.className = charClass(c);
    span.textContent = c;
    return span;
  }));
}

function showWords(words) {
  $('d-fp').replaceChildren(...words.split(' ').map((word, i) => {
    const chip = document.createElement('span');
    chip.textContent = word;
    chip.style.setProperty('--i', i);
    return chip;
  }));
}

function setBusy(busy) {
  form.classList.toggle('busy-state', busy);
  if (busy) {
    $('d-fp').replaceChildren(...Array.from({ length: 4 }, () => document.createElement('span')));
    $('d-pw').textContent = 'Running 600,000 PBKDF2 rounds…';
    shown = { fp: '', pw: '' };
  }
}

function setStrength(length, list) {
  const bits = estimateBits(length, list);
  $('d-bits').textContent = `≈ ${bits} bits of entropy`;
  $('d-bar').style.width = `${Math.min(100, (bits / 128) * 100)}%`;
  $('d-bar').dataset.level = bits < 60 ? 'weak' : bits < 90 ? 'ok' : 'strong';
}

async function update({ rotated = false } = {}) {
  const current = ++run;
  const identity = $('d-identity').value;
  const pass = $('d-pass').value;
  const site = normalizeSite($('d-site').value);
  const length = Number($('d-length').value);
  const list = groups();
  $('d-site-norm').textContent = site || '…';
  $('d-ver').textContent = `v${counter}`;
  $('d-len-val').textContent = length;
  $('d-err').textContent = '';
  for (const chip of $('d-chips').children) chip.classList.toggle('on', chip.textContent === site);
  setStrength(length, list);
  if (!rotated) $('d-old').textContent = '';
  try {
    const id = `${identity}\n${pass}`;
    if (keyCache.id !== id) {
      setBusy(true);
      keyCache = { id, key: await deriveKeys(pass, identity, SALT) };
    }
    if (current !== run) return;
    setBusy(false);
    if (shown.fp !== keyCache.key.fingerprint) {
      shown.fp = keyCache.key.fingerprint;
      showWords(shown.fp);
    }
    if (!site) throw new Error('Enter a website.');
    const previous = shown.pw;
    const password = await derivePassword(keyCache.key.siteKey, { site, counter, length, groups: list });
    if (current !== run || password === shown.pw) return;
    shown.pw = password;
    if (rotated && previous) {
      $('d-old').innerHTML = '';
      $('d-old').append(`v${counter - 1} `, Object.assign(document.createElement('s'), { textContent: previous }),
        ' still shown until you update the site');
    }
    const pw = $('d-pw');
    scramble(pw, password, 700, () => { if (shown.pw === password) colorize(pw, password); });
  } catch (error) {
    if (current !== run) return;
    setBusy(false);
    if (keyCache.id !== `${identity}\n${pass}` || !keyCache.key) {
      keyCache = { id: '', key: null };
      $('d-fp').replaceChildren();
    }
    shown.pw = '';
    $('d-pw').textContent = '—';
    $('d-err').textContent = error.message;
  }
}

let timer;
const later = () => { clearTimeout(timer); timer = setTimeout(update, 300); };
form.addEventListener('input', (event) => {
  if (event.target.id === 'd-site') counter = 1;
  if (event.target.type === 'range' || event.target.type === 'checkbox') update(); else later();
});
form.addEventListener('submit', (event) => event.preventDefault());

$('d-groups').addEventListener('click', (event) => {
  if (event.target.type === 'checkbox' && !event.target.checked && groups().length === 0) event.preventDefault();
});
$('d-chips').addEventListener('click', (event) => {
  if (event.target.tagName !== 'BUTTON') return;
  $('d-site').value = event.target.textContent;
  counter = 1;
  update();
});
$('d-rotate').addEventListener('click', () => {
  counter += 1;
  const icon = $('d-rotate').querySelector('svg');
  icon.classList.remove('turn');
  void icon.getBoundingClientRect();
  icon.classList.add('turn');
  update({ rotated: true });
});
$('d-eye').addEventListener('click', () => {
  const input = $('d-pass');
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  $('d-eye').setAttribute('aria-pressed', String(show));
  $('d-eye').setAttribute('aria-label', show ? 'Hide passphrase' : 'Show passphrase');
});
$('d-copy').addEventListener('click', async () => {
  if (!shown.pw) return;
  await navigator.clipboard.writeText(shown.pw);
  $('d-copy').textContent = 'Copied';
  setTimeout(() => { $('d-copy').textContent = 'Copy'; }, 1400);
});

update();
