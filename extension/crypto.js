export const ITERATIONS = 600_000;
export const MAX_BACKUP_BYTES = 8_000_000;
export const MAX_ENTRIES = 5_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const AAD = { 1: encoder.encode('EasyPwd vault format 1'), 2: encoder.encode('EasyPwd vault format 2') };
const DERIVE_LABEL = 'easypwd/v2/site-password';

// Part of the derivation format: changing these strings changes every generated password.
export const GROUPS = Object.freeze({
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}:,.?',
});
export const GROUP_ORDER = Object.freeze(Object.keys(GROUPS));
export const DEFAULT_RULES = Object.freeze({ length: 20, groups: GROUP_ORDER });

export const FINGERPRINT_WORDS = Object.freeze([
  'apple', 'anchor', 'arrow', 'badge', 'bamboo', 'banjo', 'beacon', 'bison',
  'blossom', 'bridge', 'cactus', 'camel', 'canyon', 'cedar', 'cobalt', 'comet',
  'coral', 'crane', 'daisy', 'delta', 'dune', 'eagle', 'ember', 'falcon',
  'fern', 'fjord', 'garnet', 'glacier', 'harbor', 'hazel', 'heron', 'igloo',
  'ivory', 'jasmine', 'jungle', 'kayak', 'koala', 'lagoon', 'lantern', 'lemon',
  'lotus', 'maple', 'meadow', 'mango', 'nebula', 'nectar', 'oasis', 'olive',
  'orbit', 'otter', 'panda', 'pepper', 'pebble', 'quartz', 'raven', 'river',
  'saffron', 'sierra', 'tiger', 'tulip', 'velvet', 'walnut', 'willow', 'zebra',
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  return isObject(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function toBase64(bytes) {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(''));
}

function fromBase64(value, length) {
  if (typeof value !== 'string' || value.length > MAX_BACKUP_BYTES ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Invalid encrypted vault encoding.');
  }
  const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  if ((length !== undefined && bytes.length !== length) || toBase64(bytes) !== value) {
    throw new Error('Invalid encrypted vault encoding.');
  }
  return bytes;
}

// ---------- Identifiers ----------

export function normalizeIdentity(value) {
  const identity = typeof value === 'string' ? value.normalize('NFC').trim().toLowerCase() : '';
  if (!identity || identity.length > 256) throw new Error('Enter your email or name (up to 256 characters).');
  return identity;
}

// "https://www.GitHub.com/login" and "github.com" both become "github.com".
export function normalizeSite(value) {
  if (typeof value !== 'string') return '';
  let site = value.normalize('NFC').trim().toLowerCase();
  if (/^[a-z][a-z\d+.-]*:\/\//.test(site)) {
    try { site = new URL(site).hostname; } catch { /* keep as typed */ }
  } else if (/^[^\s/?#]+\.[^\s/?#]+(?:[/?#]|$)/.test(site)) {
    site = site.split(/[/?#]/)[0];
  }
  return site.replace(/^www\./, '').replace(/\.$/, '');
}

export function validRules(length, groups) {
  return Number.isInteger(length) && length >= 8 && length <= 64 &&
    Array.isArray(groups) && groups.length > 0 &&
    groups.every((group, index) => GROUP_ORDER.includes(group) &&
      (index === 0 || GROUP_ORDER.indexOf(group) > GROUP_ORDER.indexOf(groups[index - 1])));
}

// ---------- Validation ----------

export function validateEnvelope(value) {
  const v1 = exactKeys(value, ['format', 'version', 'kdf', 'salt', 'iv', 'ciphertext']) && value.version === 1;
  const v2 = exactKeys(value, ['format', 'version', 'identity', 'kdf', 'salt', 'iv', 'ciphertext']) && value.version === 2;
  let identityOk = v1;
  if (v2) {
    try { identityOk = normalizeIdentity(value.identity) === value.identity; } catch { identityOk = false; }
  }
  if (!(v1 || v2) || !identityOk || value.format !== 'easypwd' ||
      !exactKeys(value.kdf, ['name', 'hash', 'iterations']) ||
      value.kdf.name !== 'PBKDF2' || value.kdf.hash !== 'SHA-256' ||
      value.kdf.iterations !== ITERATIONS) {
    throw new Error('Unsupported or invalid vault format. The existing vault has not been changed.');
  }
  fromBase64(value.salt, 16);
  fromBase64(value.iv, 12);
  if (fromBase64(value.ciphertext).length < 16 ||
      encoder.encode(JSON.stringify(value)).length > MAX_BACKUP_BYTES) {
    throw new Error('Invalid encrypted vault size.');
  }
  return value;
}

const ENTRY_KEYS = ['id', 'name', 'url', 'username', 'password', 'notes'];
const OPTIONAL_KEYS = ['updatedAt', 'derive', 'otp'];

export function validateEntries(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) {
    throw new Error(`A vault must contain no more than ${MAX_ENTRIES} entries.`);
  }
  const ids = new Set();
  for (const entry of entries) {
    if (!isObject(entry) || !ENTRY_KEYS.every((key) => Object.hasOwn(entry, key)) ||
        Object.keys(entry).some((key) => !ENTRY_KEYS.includes(key) && !OPTIONAL_KEYS.includes(key)) ||
        (Object.hasOwn(entry, 'updatedAt') && (!Number.isSafeInteger(entry.updatedAt) || entry.updatedAt < 0)) ||
        typeof entry.id !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(entry.id) ||
        ids.has(entry.id)) {
      throw new Error('Invalid or duplicate vault entry.');
    }
    ids.add(entry.id);
    for (const field of ['name', 'url', 'username', 'password', 'notes']) {
      const limit = field === 'notes' ? 4_000 : 1_024;
      if (typeof entry[field] !== 'string' || entry[field].length > limit) {
        throw new Error(`Invalid entry field: ${field}.`);
      }
    }
    if (Object.hasOwn(entry, 'derive')) {
      const { derive } = entry;
      if (!exactKeys(derive, ['site', 'counter', 'length', 'groups']) ||
          typeof derive.site !== 'string' || !derive.site || derive.site.length > 1_024 ||
          normalizeSite(derive.site) !== derive.site ||
          !Number.isSafeInteger(derive.counter) || derive.counter < 1 || derive.counter > 1_000_000 ||
          !validRules(derive.length, derive.groups) || entry.password !== '') {
        throw new Error('Invalid generated-password settings.');
      }
      if (!entry.name.trim()) throw new Error('Every entry needs a name and a password.');
    } else if (!entry.name.trim() || !entry.password) {
      throw new Error('Every entry needs a name and a password.');
    }
    if (Object.hasOwn(entry, 'otp')) validateOtp(entry.otp);
    if (entry.url) {
      let url;
      try {
        url = new URL(entry.url);
      } catch {
        throw new Error('Website must be a complete HTTP or HTTPS URL.');
      }
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) {
        throw new Error('Website must be an HTTP or HTTPS URL without embedded credentials.');
      }
    }
  }
  return entries;
}

export function validateNewMasterPassword(password) {
  if (typeof password !== 'string' || password.length < 15 || password.length > 1_024) {
    throw new Error('Use a master passphrase of 15 to 1,024 characters. Several unrelated words work well.');
  }
}

function checkPassword(password) {
  if (typeof password !== 'string' || !password || password.length > 1_024) {
    throw new Error('Enter your master passphrase (up to 1,024 characters).');
  }
}

// ---------- Key derivation ----------

// Format 1: the passphrase directly derives the vault key with a random salt.
export async function deriveKey(password, salt) {
  checkPassword(password);
  const bytes = encoder.encode(password);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64(salt, 16), iterations: ITERATIONS },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
  } finally {
    bytes.fill(0);
  }
}

// Format 2: passphrase + identity derive a root key that is the same on every device.
// The vault key, site-password key, and fingerprint are separated with HKDF.
export async function deriveKeys(password, identity, vaultSalt) {
  checkPassword(password);
  const bytes = encoder.encode(password.normalize('NFC'));
  let root;
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({
      name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS,
      salt: encoder.encode(`easypwd/v2/identity\n${normalizeIdentity(identity)}`),
    }, material, 256));
    try {
      root = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey', 'deriveBits']);
    } finally {
      bits.fill(0);
    }
  } finally {
    bytes.fill(0);
  }
  const hkdf = (info, salt = new Uint8Array(0)) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(info) });
  const [siteKey, key, print] = await Promise.all([
    crypto.subtle.deriveKey(hkdf('easypwd/v2/site-passwords'), root,
      { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']),
    crypto.subtle.deriveKey(hkdf('easypwd/v2/vault', fromBase64(vaultSalt, 16)), root,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    crypto.subtle.deriveBits(hkdf('easypwd/v2/fingerprint'), root, 24),
  ]);
  const [a, b, c] = new Uint8Array(print);
  const value = (a << 16) | (b << 8) | c;
  const fingerprint = [18, 12, 6, 0].map((shift) => FINGERPRINT_WORDS[(value >> shift) & 63]).join(' ');
  return { key, siteKey, fingerprint };
}

// ---------- Vault encryption ----------

export async function encryptVault(entries, key, salt, identity) {
  validateEntries(entries);
  const version = identity === undefined ? 1 : 2;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify({ entries }));
  try {
    if (plaintext.length > MAX_BACKUP_BYTES * 0.7) throw new Error('The vault is too large. No changes were saved.');
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: AAD[version], tagLength: 128 }, key, plaintext,
    );
    return validateEnvelope({
      format: 'easypwd', version, ...(version === 2 ? { identity } : {}),
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS },
      salt, iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertext)),
    });
  } finally {
    plaintext.fill(0);
  }
}

// Encrypts entries under a fresh salt (new vault, upgrade, or passphrase change).
export async function sealVault(entries, password, identity) {
  validateNewMasterPassword(password);
  const normalized = normalizeIdentity(identity);
  const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
  const keys = await deriveKeys(password, normalized, salt);
  const envelope = await encryptVault(entries, keys.key, salt, normalized);
  return { ...keys, version: 2, identity: normalized, envelope, entries };
}

export const createVault = (password, identity) => sealVault([], password, identity);

async function decryptBytes(envelope, key) {
  return new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: fromBase64(envelope.iv, 12), additionalData: AAD[envelope.version], tagLength: 128,
  }, key, fromBase64(envelope.ciphertext)));
}

function readPlaintext(plaintext) {
  try {
    const value = JSON.parse(decoder.decode(plaintext));
    if (!exactKeys(value, ['entries'])) throw new Error('Invalid decrypted vault format.');
    return validateEntries(value.entries);
  } finally {
    plaintext.fill(0);
  }
}

export async function unlockVault(envelope, password) {
  validateEnvelope(envelope);
  checkPassword(password);
  if (envelope.version === 2) {
    const keys = await deriveKeys(password, envelope.identity, envelope.salt);
    let plaintext;
    try {
      plaintext = await decryptBytes(envelope, keys.key);
    } catch {
      throw new Error('Incorrect master passphrase.');
    }
    return { ...keys, version: 2, identity: envelope.identity, envelope, entries: readPlaintext(plaintext) };
  }
  // Format 1: try the normalized form first, then the raw input from before normalization.
  for (const candidate of new Set([password.normalize('NFC'), password])) {
    const key = await deriveKey(candidate, envelope.salt);
    let plaintext;
    try {
      plaintext = await decryptBytes(envelope, key);
    } catch {
      continue;
    }
    return { version: 1, key, envelope, entries: readPlaintext(plaintext) };
  }
  throw new Error('Incorrect master passphrase.');
}

export function parseBackup(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > MAX_BACKUP_BYTES) {
    throw new Error(`Backup exceeds the ${MAX_BACKUP_BYTES / 1e6} MB size limit.`);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('The backup is not valid JSON.');
  }
  return validateEnvelope(value);
}

// ---------- Passwords ----------

function coversGroups(password, groups) {
  return groups.every((group) => [...password].some((character) => GROUPS[group].includes(character)));
}

export function estimateBits(length, groups) {
  const size = groups.reduce((total, group) => total + GROUPS[group].length, 0);
  return Math.floor(length * Math.log2(size));
}

// Deterministic: the same key, site, version, and rules always give the same password.
export async function derivePassword(siteKey, { site, counter, length, groups }) {
  if (typeof site !== 'string' || !site || normalizeSite(site) !== site ||
      !Number.isSafeInteger(counter) || counter < 1 || !validRules(length, groups)) {
    throw new Error('Invalid generated-password settings.');
  }
  const alphabet = groups.map((group) => GROUPS[group]).join('');
  const threshold = 256 - (256 % alphabet.length);
  let block = 0;
  let bytes = new Uint8Array(0);
  let offset = 0;
  const nextByte = async () => {
    if (offset === bytes.length) {
      const input = encoder.encode(JSON.stringify([DERIVE_LABEL, site, counter, length, groups, block]));
      bytes = new Uint8Array(await crypto.subtle.sign('HMAC', siteKey, input));
      block += 1;
      offset = 0;
    }
    return bytes[offset++];
  };
  // Rejection sampling avoids modulo bias; whole candidates are rejected if a group is missing.
  for (;;) {
    let password = '';
    while (password.length < length) {
      const byte = await nextByte();
      if (byte < threshold) password += alphabet[byte % alphabet.length];
    }
    if (coversGroups(password, groups)) return password;
  }
}

function randomIndex(limit) {
  const threshold = 256 - (256 % limit);
  const byte = new Uint8Array(1);
  do { crypto.getRandomValues(byte); } while (byte[0] >= threshold);
  return byte[0] % limit;
}

export function generatePassword(length = 20, groups = GROUP_ORDER) {
  if (!Number.isInteger(length) || length < 8 || length > 128 ||
      !Array.isArray(groups) || !groups.length || new Set(groups).size !== groups.length ||
      groups.some((group) => !Object.hasOwn(GROUPS, group))) {
    throw new Error('Choose a length from 8 to 128 and at least one character group.');
  }
  const alphabet = groups.map((group) => GROUPS[group]).join('');
  for (;;) {
    const password = Array.from({ length }, () => alphabet[randomIndex(alphabet.length)]).join('');
    if (coversGroups(password, groups)) return password;
  }
}

// ---------- Two-factor codes (TOTP, RFC 6238) ----------

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const OTP_ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export function validateOtp(otp) {
  if (!exactKeys(otp, ['secret', 'digits', 'period', 'algorithm']) ||
      typeof otp.secret !== 'string' || !/^[A-Z2-7]{16,256}$/.test(otp.secret) ||
      ![6, 7, 8].includes(otp.digits) ||
      !Number.isInteger(otp.period) || otp.period < 10 || otp.period > 300 ||
      !Object.hasOwn(OTP_ALGORITHMS, otp.algorithm)) {
    throw new Error('Invalid two-factor settings.');
  }
  return otp;
}

function base32Decode(secret) {
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const character of secret) {
    buffer = (buffer << 5) | BASE32.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 255);
    }
  }
  return new Uint8Array(bytes);
}

// Accepts a setup key ("JBSW Y3DP EHPK 3PXP") or an otpauth://totp/... link.
// Returns the settings plus the issuer and account name when the link has them.
export function parseOtp(input) {
  const text = typeof input === 'string' ? input.trim() : '';
  const invalid = 'Paste the setup key or otpauth:// link from the website’s two-factor setup.';
  const otp = { secret: '', digits: 6, period: 30, algorithm: 'SHA1' };
  let issuer = '';
  let account = '';
  if (/^otpauth:/i.test(text)) {
    let url;
    try { url = new URL(text); } catch { throw new Error(invalid); }
    if (url.hostname.toLowerCase() !== 'totp') {
      throw new Error('Only time-based codes (TOTP) are supported, not counter-based ones (HOTP).');
    }
    const params = url.searchParams;
    otp.secret = params.get('secret') ?? '';
    if (params.has('digits')) otp.digits = Number(params.get('digits'));
    if (params.has('period')) otp.period = Number(params.get('period'));
    if (params.has('algorithm')) otp.algorithm = params.get('algorithm').toUpperCase().replace('-', '');
    let label = '';
    try { label = decodeURIComponent(url.pathname.replace(/^\/+/, '')); } catch { /* keep empty */ }
    const colon = label.indexOf(':');
    account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
    issuer = (params.get('issuer') ?? (colon >= 0 ? label.slice(0, colon) : '')).trim();
  } else {
    otp.secret = text;
  }
  otp.secret = otp.secret.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  try {
    validateOtp(otp);
  } catch {
    throw new Error(/^[A-Z2-7]*$/.test(otp.secret) && otp.secret.length < 16 ?
      'That setup key is too short. Check that you copied all of it.' : invalid);
  }
  return { otp, issuer: issuer.slice(0, 1_024), account: account.slice(0, 1_024) };
}

// Returns the current code and how many seconds it stays valid.
export async function totp(otp, now = Date.now()) {
  validateOtp(otp);
  const step = Math.floor(now / 1000 / otp.period);
  const message = new DataView(new ArrayBuffer(8));
  message.setUint32(0, Math.floor(step / 2 ** 32));
  message.setUint32(4, step >>> 0);
  const secret = base32Decode(otp.secret);
  try {
    const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: OTP_ALGORITHMS[otp.algorithm] }, false, ['sign']);
    const hash = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
    const offset = hash[hash.length - 1] & 15;
    const value = ((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
    const code = String(value % 10 ** otp.digits).padStart(otp.digits, '0');
    return { code, remaining: otp.period - (Math.floor(now / 1000) % otp.period), period: otp.period };
  } finally {
    secret.fill(0);
  }
}
