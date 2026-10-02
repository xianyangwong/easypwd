import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createVault, unlockVault, encryptVault, parseBackup, validateEnvelope,
  validateEntries, generatePassword, ITERATIONS, MAX_BACKUP_BYTES,
  sealVault, estimateBits, deriveKey, deriveKeys, derivePassword, normalizeSite, normalizeIdentity,
  FINGERPRINT_WORDS, GROUPS, parseOtp, totp, DEFAULT_RULES,
} from '../extension/crypto.js';
import { guessSite, lookup, siteMatches } from '../extension/lookup.js';
import { createHmac, hkdfSync, pbkdf2Sync } from 'node:crypto';
import { parseCsv, entriesFromChromeCsv } from '../extension/csv.js';
import { VaultStorage, STORAGE_KEY, sameVault } from '../extension/storage.js';

const master = 'an unrelated set of words for testing';
const identity = 'test@example.com';
const entry = {
  id: '12345678-1234-4123-8123-123456789abc',
  name: 'Personal email', url: 'https://example.com',
  username: 'test@example.com', password: 'Example-only-password-73!', notes: 'Private test note.',
};
const clone = (value) => structuredClone(value);

test('vault round trip, authenticated encryption, backup, and input boundaries', async () => {
  const created = await createVault(master, identity);
  assert.equal(created.key.extractable, false);
  assert.equal(created.envelope.kdf.iterations, ITERATIONS);
  assert.deepEqual((await unlockVault(created.envelope, master)).entries, []);
  const saved = await encryptVault([entry], created.key, created.envelope.salt, identity);
  const secondSave = await encryptVault([entry], created.key, created.envelope.salt, identity);
  assert.notEqual(saved.iv, secondSave.iv);
  assert.notEqual(saved.ciphertext, secondSave.ciphertext);
  const serialized = JSON.stringify(saved);
  for (const secret of [master, entry.name, entry.password, entry.notes]) {
    assert.equal(serialized.includes(secret), false);
  }
  const backup = parseBackup(serialized);
  assert.deepEqual((await unlockVault(backup, master)).entries, [entry]);
  for (const payload of [
    { entries: [{ ...entry, password: '' }] },
    { entries: [entry, entry] },
    { entries: [], extra: true },
  ]) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({
      name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('EasyPwd vault format 2'),
    }, created.key, new TextEncoder().encode(JSON.stringify(payload)));
    await assert.rejects(unlockVault({
      ...saved, iv: Buffer.from(iv).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64'),
    }, master));
  }
  await assert.rejects(unlockVault(saved, 'wrong passphrase'), /Incorrect master passphrase/);
  for (const field of ['ciphertext', 'iv', 'salt']) {
    const altered = clone(saved);
    const bytes = Buffer.from(altered[field], 'base64');
    bytes[0] ^= 1;
    altered[field] = bytes.toString('base64');
    await assert.rejects(unlockVault(altered, master), /Incorrect master passphrase/);
  }
  for (const mutation of [
    (value) => { value.version = 1; },
    (value) => { value.version = 3; },
    (value) => { value.identity = 'Test@Example.com'; },
    (value) => { delete value.identity; },
    (value) => { value.kdf.iterations = 1; },
    (value) => { value.kdf.iterations = 10_000_000_000; },
    (value) => { value.salt = ''; },
    (value) => { value.iv = 'not base64'; },
    (value) => { value.ciphertext = 'AAAA'; },
    (value) => { value.unexpected = true; },
  ]) {
    const invalid = clone(saved);
    mutation(invalid);
    assert.throws(() => validateEnvelope(invalid));
  }
  assert.throws(() => parseBackup('{'), /not valid JSON/);
  assert.throws(() => parseBackup('x'.repeat(MAX_BACKUP_BYTES + 1)), /size limit/);
  await assert.rejects(createVault('short', identity), /15 to 1,024/);
  await assert.rejects(createVault('x'.repeat(1025), identity), /15 to 1,024/);
  await assert.rejects(createVault(master, ' '), /email or name/);
  assert.throws(() => validateEntries([entry, entry]), /duplicate/);
  assert.throws(() => validateEntries([{ ...entry, name: ' ' }]), /name and a password/);
  assert.throws(() => validateEntries([{ ...entry, password: '' }]), /name and a password/);
  assert.throws(() => validateEntries([{ ...entry, notes: 'x'.repeat(4001) }]), /notes/);
  for (const url of ['javascript:alert(1)', 'ftp://example.com', 'https://user:secret@example.com', 'example.com']) {
    assert.throws(() => validateEntries([{ ...entry, url }]), /Website/);
  }
  assert.deepEqual(validateEntries([{ ...entry, name: 'Email <script>', notes: '日本語' }])[0].notes, '日本語');
});

test('password generator respects length and chosen groups without weak randomness', () => {
  const values = new Set();
  for (let i = 0; i < 100; i += 1) {
    const password = generatePassword();
    assert.equal(password.length, 20);
    assert.match(password, /[a-z]/);
    assert.match(password, /[A-Z]/);
    assert.match(password, /[0-9]/);
    assert.match(password, /[^a-zA-Z0-9]/);
    values.add(password);
  }
  assert.equal(values.size, 100);
  assert.match(generatePassword(128, ['digits']), /^[0-9]{128}$/);
  assert.match(generatePassword(8, ['lowercase']), /^[a-z]{8}$/);
  for (const args of [[7], [129], [20.5], [20, []], [20, ['invalid']], [20, ['digits', 'digits']]]) {
    assert.throws(() => generatePassword(...args), /Choose a length/);
  }
});

function memoryStorage() {
  let value = null;
  let fail = false;
  let queue = Promise.resolve();
  const area = {
    async get() { return value === null ? {} : { [STORAGE_KEY]: clone(value) }; },
    async set(next) {
      if (fail) throw new Error('Storage quota exceeded.');
      value = clone(next[STORAGE_KEY]);
    },
    async remove(key) {
      assert.equal(key, STORAGE_KEY);
      value = null;
    },
  };
  const locks = {
    request(name, action) {
      assert.equal(name, 'easypwd-vault-write');
      const result = queue.then(action);
      queue = result.catch(() => {});
      return result;
    },
  };
  return { storage: new VaultStorage(area, locks), failWrites() { fail = true; } };
}

test('storage does not overwrite concurrent changes, failed writes, or locked sessions', async () => {
  const { storage, failWrites } = memoryStorage();
  assert.equal(await storage.read(), null);
  const first = { ciphertext: 'first' };
  const second = { ciphertext: 'second' };
  await storage.replace(null, first);
  const results = await Promise.allSettled([
    storage.replace(first, second),
    storage.replace(first, { ciphertext: 'stale' }),
  ]);
  assert.equal(results[0].status, 'fulfilled');
  assert.equal(results[1].status, 'rejected');
  assert.match(results[1].reason.message, /another tab/);
  assert.deepEqual(await storage.read(), second);
  await assert.rejects(storage.replace(second, first, () => false), /locked/);
  assert.deepEqual(await storage.read(), second);
  failWrites();
  await assert.rejects(storage.replace(second, first), /quota/);
  assert.deepEqual(await storage.read(), second);
});

test('storage deletes the vault only when the expected value still matches', async () => {
  const { storage } = memoryStorage();
  const value = { ciphertext: 'value' };
  await storage.replace(null, value);
  await assert.rejects(storage.replace({ ciphertext: 'other' }, null), /another tab/);
  await storage.replace(value, null);
  assert.equal(await storage.read(), null);
});

test('vault comparisons ignore Chrome storage object-key reordering, not changed values', () => {
  const original = { version: 1, kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS }, salt: 'abc' };
  const reordered = { salt: 'abc', kdf: { iterations: ITERATIONS, hash: 'SHA-256', name: 'PBKDF2' }, version: 1 };
  assert.equal(sameVault(original, reordered), true);
  assert.equal(sameVault(original, { ...reordered, salt: 'changed' }), false);
  assert.equal(sameVault(null, original), false);
  assert.equal(sameVault(null, null), true);
});

test('entries accept an optional edit timestamp only', () => {
  assert.doesNotThrow(() => validateEntries([{ ...entry, updatedAt: 1_700_000_000_000 }]));
  assert.throws(() => validateEntries([{ ...entry, updatedAt: -1 }]));
  assert.throws(() => validateEntries([{ ...entry, updatedAt: '2024' }]));
  assert.throws(() => validateEntries([{ ...entry, extra: true }]));
});

test('sealing re-keys the vault and passphrases are Unicode-normalized', async () => {
  const decomposed = 'cafe\u0301 correct horse battery staple';
  const composed = decomposed.normalize('NFC');
  const sealed = await sealVault([entry], decomposed, identity);
  assert.deepEqual((await unlockVault(sealed.envelope, composed)).entries, [entry]);
  assert.deepEqual((await unlockVault(sealed.envelope, decomposed)).entries, [entry]);
  const rekeyed = await sealVault([entry], 'a completely different passphrase', identity);
  assert.notEqual(rekeyed.envelope.salt, sealed.envelope.salt);
  await assert.rejects(unlockVault(rekeyed.envelope, decomposed), /Incorrect/);
  assert.equal(estimateBits(20, ['lowercase']), Math.floor(20 * Math.log2(26)));
});

test('Chrome CSV import handles quoting, BOM, bad URLs, and invalid rows', () => {
  assert.deepEqual(parseCsv('a,"b,c","d ""q"""\r\n"multi\nline",x,\n'), [['a', 'b,c', 'd "q"'], ['multi\nline', 'x', '']]);
  assert.throws(() => parseCsv('"open'), /unclosed/);
  const csv = '\uFEFFname,url,username,password,note\n' +
    'GitHub,https://github.com/login,me,pw1,"hello, world"\n' +
    ',https://www.example.com/,you,pw2,\n' +
    'App,android://abc@com.example,app,pw3,\n' +
    `Huge,https://x.com,u,${'p'.repeat(2000)},\n`;
  const { entries, skipped } = entriesFromChromeCsv(csv, 42);
  assert.equal(skipped, 1);
  assert.deepEqual(entries.map(({ name, url, notes, updatedAt }) => ({ name, url, notes, updatedAt })), [
    { name: 'GitHub', url: 'https://github.com/login', notes: 'hello, world', updatedAt: 42 },
    { name: 'www.example.com', url: 'https://www.example.com/', notes: '', updatedAt: 42 },
    { name: 'App', url: '', notes: '', updatedAt: 42 },
  ]);
  assert.doesNotThrow(() => validateEntries(entries));
  assert.throws(() => entriesFromChromeCsv('title,login\nx,y'), /Chrome password export/);
});

test('generated passwords are stable across devices and pinned to the format', async () => {
  const one = await createVault(master, 'Test@Example.com ');
  const two = await createVault(master, identity);
  assert.equal(one.identity, identity);
  assert.notEqual(one.envelope.salt, two.envelope.salt);
  assert.equal(one.fingerprint, two.fingerprint);
  assert.equal(one.fingerprint.split(' ').length, 4);
  assert.ok(one.fingerprint.split(' ').every((word) => FINGERPRINT_WORDS.includes(word)));
  const github = { site: 'github.com', counter: 1, length: 20, groups: ['lowercase', 'uppercase', 'digits', 'symbols'] };
  const password = await derivePassword(one.siteKey, github);
  assert.equal(password, await derivePassword(two.siteKey, github));
  assert.equal(password, await derivePassword((await unlockVault(one.envelope, master)).siteKey, github));
  // Pinned vectors: if these change, every user's generated passwords change.
  assert.equal(one.fingerprint, PINNED.fingerprint);
  assert.equal(password, PINNED.github);
  assert.equal(await derivePassword(one.siteKey, { ...github, counter: 2 }), PINNED.github2);
  assert.equal(await derivePassword(one.siteKey, { site: 'home wifi', counter: 1, length: 12, groups: ['digits'] }), PINNED.wifi);
  assert.match(password, /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^a-zA-Z0-9]).{20}$/);

  const other = await createVault(master, 'someone@example.com');
  assert.notEqual(await derivePassword(other.siteKey, github), password);
  assert.notEqual(await derivePassword(one.siteKey, { ...github, site: 'gitlab.com' }), password);
  for (let length = 8; length <= 64; length += 7) {
    assert.match(await derivePassword(one.siteKey, { ...github, length, groups: ['uppercase', 'digits'] }),
      new RegExp(`^(?=.*[A-Z])(?=.*[0-9])[A-Z0-9]{${length}}$`));
  }
  for (const bad of [
    { ...github, site: 'GitHub.com' }, { ...github, counter: 0 }, { ...github, length: 7 },
    { ...github, length: 65 }, { ...github, groups: [] }, { ...github, groups: ['digits', 'lowercase'] },
  ]) {
    await assert.rejects(derivePassword(one.siteKey, bad), /generated-password/);
  }
});

const PINNED = {
  fingerprint: 'coral igloo crane cedar',
  github: 'P]}WJFScfS=cVB57YPB9',
  github2: '?mt+dXWWFuB5G5):}?#%',
  wifi: '261169021281',
};

// An independent implementation with node:crypto. It documents the derivation for anyone porting it.
function referencePassword(passphrase, user, { site, counter, length, groups }) {
  const root = pbkdf2Sync(passphrase.normalize('NFC'), `easypwd/v2/identity\n${user}`, ITERATIONS, 32, 'sha256');
  const siteKey = Buffer.from(hkdfSync('sha256', root, Buffer.alloc(0), 'easypwd/v2/site-passwords', 32));
  const alphabet = groups.map((group) => GROUPS[group]).join('');
  const threshold = 256 - (256 % alphabet.length);
  let block = 0;
  let bytes = [];
  let offset = 0;
  const next = () => {
    if (offset === bytes.length) {
      const input = JSON.stringify(['easypwd/v2/site-password', site, counter, length, groups, block++]);
      bytes = createHmac('sha256', siteKey).update(input).digest();
      offset = 0;
    }
    return bytes[offset++];
  };
  for (;;) {
    let password = '';
    while (password.length < length) {
      const byte = next();
      if (byte < threshold) password += alphabet[byte % alphabet.length];
    }
    if (groups.every((group) => [...password].some((character) => GROUPS[group].includes(character)))) return password;
  }
}

test('the reference implementation matches the pinned vectors', () => {
  const all = ['lowercase', 'uppercase', 'digits', 'symbols'];
  assert.equal(referencePassword(master, identity, { site: 'github.com', counter: 1, length: 20, groups: all }), PINNED.github);
  assert.equal(referencePassword(master, identity, { site: 'home wifi', counter: 1, length: 12, groups: ['digits'] }), PINNED.wifi);
});

test('sites and identities normalize to the same value however they are typed', () => {
  for (const input of ['github.com', 'GitHub.com', ' https://www.github.com/login?x=1 ', 'www.github.com/', 'http://github.com.']) {
    assert.equal(normalizeSite(input), 'github.com');
  }
  assert.equal(normalizeSite('Home WiFi'), 'home wifi');
  assert.equal(normalizeSite('accounts.google.com/signin'), 'accounts.google.com');
  assert.equal(normalizeIdentity('  Me@Example.COM '), 'me@example.com');
  assert.throws(() => normalizeIdentity('x'.repeat(257)), /email or name/);
});

test('generated logins store settings instead of a password', () => {
  const generated = { ...entry, password: '', derive: { site: 'example.com', counter: 3, length: 16, groups: ['lowercase', 'digits'] } };
  assert.doesNotThrow(() => validateEntries([generated]));
  for (const derive of [
    { ...generated.derive, site: 'Example.com' }, { ...generated.derive, site: '' },
    { ...generated.derive, counter: 0 }, { ...generated.derive, counter: 1.5 },
    { ...generated.derive, length: 100 }, { ...generated.derive, groups: ['digits', 'lowercase'] },
    { ...generated.derive, groups: ['digits', 'digits'] }, { ...generated.derive, extra: 1 },
  ]) {
    assert.throws(() => validateEntries([{ ...generated, derive }]), /generated-password/);
  }
  assert.throws(() => validateEntries([{ ...generated, password: 'stored too' }]), /generated-password/);
});

test('format 1 vaults still unlock and can be upgraded with an identity', async () => {
  const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64');
  const legacy = await encryptVault([entry], await deriveKey(master, salt), salt);
  assert.equal(legacy.version, 1);
  assert.equal(Object.hasOwn(legacy, 'identity'), false);
  const opened = await unlockVault(parseBackup(JSON.stringify(legacy)), master);
  assert.equal(opened.version, 1);
  assert.equal(opened.siteKey, undefined);
  assert.deepEqual(opened.entries, [entry]);
  const upgraded = await sealVault(opened.entries, master, identity);
  assert.equal(upgraded.envelope.version, 2);
  assert.equal(upgraded.envelope.identity, identity);
  assert.deepEqual((await unlockVault(upgraded.envelope, master)).entries, [entry]);
  await assert.rejects(unlockVault(legacy, 'wrong passphrase'), /Incorrect/);
  const keys = await deriveKeys(master, identity, salt);
  assert.equal(keys.key.extractable, false);
  assert.equal(keys.siteKey.extractable, false);
});

const base32 = (text) => {
  const bits = [...Buffer.from(text)].map((byte) => byte.toString(2).padStart(8, '0')).join('');
  return bits.match(/.{1,5}/g).map((chunk) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[parseInt(chunk.padEnd(5, '0'), 2)]).join('');
};

test('two-factor codes match the RFC 6238 test vectors', async () => {
  const secrets = {
    SHA1: base32('12345678901234567890'),
    SHA256: base32('12345678901234567890123456789012'),
    SHA512: base32('1234567890'.repeat(6) + '1234'),
  };
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [time, ...codes] of vectors) {
    for (const [index, algorithm] of ['SHA1', 'SHA256', 'SHA512'].entries()) {
      const result = await totp({ secret: secrets[algorithm], digits: 8, period: 30, algorithm }, time * 1000);
      assert.equal(result.code, codes[index], `${algorithm} at ${time}`);
    }
  }
  const six = await totp({ secret: secrets.SHA1, digits: 6, period: 30, algorithm: 'SHA1' }, 59_000);
  assert.deepEqual(six, { code: '287082', remaining: 1, period: 30 });
});

test('two-factor setup keys and otpauth links parse strictly', () => {
  assert.deepEqual(parseOtp(' jbsw y3dp-ehpk 3pxp== ').otp, { secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algorithm: 'SHA1' });
  assert.deepEqual(
    parseOtp('otpauth://totp/ACME%20Co:jane%40example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60'),
    { otp: { secret: 'JBSWY3DPEHPK3PXP', digits: 8, period: 60, algorithm: 'SHA256' }, issuer: 'ACME Co', account: 'jane@example.com' },
  );
  assert.equal(parseOtp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=GitHub').issuer, 'GitHub');
  assert.throws(() => parseOtp('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1'), /HOTP/);
  assert.throws(() => parseOtp('JBSWY3DP'), /too short/);
  assert.throws(() => parseOtp('not a key 0189'));
  assert.throws(() => parseOtp('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9'));
  assert.throws(() => parseOtp(''));

  const otp = { secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algorithm: 'SHA1' };
  assert.doesNotThrow(() => validateEntries([{ ...entry, otp }]));
  assert.throws(() => validateEntries([{ ...entry, otp: { ...otp, extra: 1 } }]));
  assert.throws(() => validateEntries([{ ...entry, otp: { ...otp, secret: 'jbswy3dpehpk3pxp' } }]));
  assert.throws(() => validateEntries([{ ...entry, otp: { ...otp, period: 5 } }]));
  assert.throws(() => validateEntries([{ ...entry, otp: { ...otp, algorithm: 'MD5' } }]));
});

test('the popup finds logins for the current site and suggests one otherwise', async () => {
  assert.ok(siteMatches('google.com', 'accounts.google.com'));
  assert.ok(siteMatches('accounts.google.com', 'google.com'));
  assert.ok(!siteMatches('google.com', 'notgoogle.com'));
  assert.ok(!siteMatches('com', 'example.com'));
  assert.equal(guessSite('accounts.google.com'), 'google.com');
  assert.equal(guessSite('www.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(guessSite('localhost'), 'localhost');
  assert.equal(guessSite('192.168.1.10'), '192.168.1.10');

  const { siteKey, entries } = await sealVault([], master, identity);
  const otp = { secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algorithm: 'SHA1' };
  const generated = { ...entry, id: 'b', name: 'GitHub', url: 'https://github.com', password: '', derive: { site: 'github.com', counter: 2, ...DEFAULT_RULES }, otp };
  const saved = { ...entry, id: 'a', url: 'https://mail.example.com/login' };
  const vault = { siteKey, entries: [...entries, generated, saved] };

  const github = await lookup(vault, { host: 'github.com', site: 'github.com' });
  assert.equal(github.matches.length, 1);
  assert.equal(github.matches[0].password, await derivePassword(siteKey, generated.derive));
  assert.match(github.matches[0].otp.code, /^\d{6}$/);

  const mail = await lookup(vault, { host: 'example.com', site: 'example.com' });
  assert.deepEqual(mail.matches.map((match) => match.password), [entry.password]);

  const none = await lookup(vault, { host: 'news.ycombinator.com', site: 'ycombinator.com' });
  assert.equal(none.matches.length, 0);
  assert.equal(none.suggestion.site, 'ycombinator.com');
  assert.equal(none.suggestion.password, await derivePassword(siteKey, { site: 'ycombinator.com', counter: 1, ...DEFAULT_RULES }));
});
