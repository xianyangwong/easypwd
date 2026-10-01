import { deriveKeys, derivePassword, normalizeSite, GROUP_ORDER } from './crypto.js';

const $ = (id) => document.getElementById(id);
const SALT = 'AAAAAAAAAAAAAAAAAAAAAA==';
let keyCache = { id: '', key: null };
let run = 0;

async function update() {
  const current = ++run;
  const identity = $('d-identity').value;
  const pass = $('d-pass').value;
  const site = normalizeSite($('d-site').value);
  $('d-site-norm').textContent = site || '…';
  $('d-err').textContent = '';
  try {
    const id = `${identity}\n${pass}`;
    if (keyCache.id !== id) {
      $('d-fp').textContent = 'Calculating…';
      $('d-pw').textContent = '…';
      keyCache = { id, key: await deriveKeys(pass, identity, SALT) };
    }
    if (current !== run) return;
    $('d-fp').textContent = keyCache.key.fingerprint;
    if (!site) throw new Error('Enter a website.');
    const password = await derivePassword(keyCache.key.siteKey, {
      site, counter: Number($('d-counter').value), length: Number($('d-length').value), groups: [...GROUP_ORDER],
    });
    if (current !== run) return;
    $('d-pw').textContent = password;
  } catch (error) {
    if (current !== run) return;
    if (!keyCache.key || keyCache.id !== `${identity}\n${pass}`) {
      keyCache = { id: '', key: null };
      $('d-fp').textContent = '—';
    }
    $('d-pw').textContent = '—';
    $('d-err').textContent = /settings/.test(error.message) ? 'Version must be 1 or more; length 8–64.' : error.message;
  }
}

let timer;
$('demo').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(update, 350); });
$('demo').addEventListener('submit', (event) => event.preventDefault());
update();
