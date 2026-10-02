# Security policy and boundaries

EasyPwd is an early preview and has not received an independent security audit.
Do not treat it as a replacement for a mature password manager for high-value
accounts. Do not put real credentials, master passphrases, or vault backups in
issues, pull requests, logs, or screenshots.

## Reporting a vulnerability

Use this repository's GitHub **Report a vulnerability** feature if private
vulnerability reporting is enabled. If unavailable, open an issue requesting a
private contact channel without publishing exploit details or sensitive data.

## Threat model

The goal is to keep persisted credential contents encrypted and avoid sending
secrets off-device. An attacker who obtains only an encrypted vault or backup
should need to guess the master passphrase to decrypt it. Generated passwords
should be independent of one another: learning one site's password should not
reveal another's without also guessing the passphrase. A strong passphrase is
essential. Authenticated encryption detects modifications; it does not prevent
deletion or detect replacement with an older, valid backup.

This extension does **not** protect against:

- Malware, keyloggers, compromised Chrome, or a compromised operating system.
- A malicious or compromised extension update or modified installation files.
- Access to the vault page while unlocked or developer tools inspecting it.
- Phishing, malicious websites, or credentials manually pasted into the wrong site.
- Clipboard readers, clipboard history, screenshots, or shoulder surfing.
- Loss of the only vault copy or forgetting the master passphrase.
- Offline guessing of a weak passphrase.
- Anyone who knows the passphrase and identity. They can calculate every
  generated password, including past and future versions, without the vault.

### Tradeoffs of generated passwords

- **One leaked site password enables offline guessing.** Together with the
  site name and the (often public) identity, it lets an attacker test
  passphrase guesses without the vault. Each guess costs 600,000 PBKDF2
  iterations, but a weak passphrase will still fall. Use a long passphrase of
  several random words.
- **The identity is not secret.** It is stored unencrypted in the vault and in
  backups so the lock screen can show it. It acts as a salt that stops one
  precomputed attack from working against every user; it does not add secrecy.
- **The fingerprint reveals 24 bits** about the root key. That is enough to
  catch typos and far too little to help an attacker: it only removes about
  1 in 16 million candidates per check, after the full PBKDF2 cost.
- **Stateless recovery depends on remembering settings.** Without the vault,
  you can recalculate any password whose site name, version, length, and
  character groups you know. Defaults are version 1, 20 characters, all groups.
- **Changing the passphrase changes every generated password.** EasyPwd
  therefore converts generated logins to saved logins first.

## Generated passwords

This is the frozen format-2 derivation. Changing any constant changes every
generated password, so changes require a new version. Pinned vectors live in
`test/vault.test.js`, which also checks the extension against an independent
implementation built on Node's `crypto` module.

1. **Identity.** Unicode NFC, trimmed, lowercased; 1–256 characters.
2. **Root key.** PBKDF2-HMAC-SHA-256, 600,000 iterations, 32 bytes.
   Password: the NFC-normalized passphrase as UTF-8. Salt: UTF-8
   `easypwd/v2/identity\n` followed by the identity.
3. **Subkeys.** HKDF-SHA-256 from the root key:

   | Purpose | HKDF salt | HKDF info | Output |
   |---|---|---|---|
   | Site passwords | empty | `easypwd/v2/site-passwords` | 256-bit HMAC-SHA-256 key |
   | Vault encryption | the vault's random 16-byte salt | `easypwd/v2/vault` | AES-256-GCM key |
   | Fingerprint | empty | `easypwd/v2/fingerprint` | 24 bits |

4. **Fingerprint.** The 24 bits, read big-endian, are split into four 6-bit
   indexes into the 64-word list `FINGERPRINT_WORDS` in `extension/crypto.js`.
5. **Site name.** NFC, trimmed, lowercased. If it starts with a URL scheme, the
   URL's hostname is used. Otherwise, if it looks like a domain, anything from
   the first `/`, `?`, or `#` is removed. Then a leading `www.` and a trailing
   `.` are removed. Other text, such as `home wifi`, is used as typed.
6. **Rules.** Length 8–64. Character groups are a non-empty subset, in this
   order, of: lowercase `a–z`; uppercase `A–Z`; digits `0–9`; symbols
   `!@#$%^&*()-_=+[]{}:,.?`. The alphabet is the selected groups concatenated
   in that order. The version (counter) starts at 1.
7. **Byte stream.** Block *i* (from 0) is HMAC-SHA-256 with the site key over
   the UTF-8 JSON array
   `["easypwd/v2/site-password", site, counter, length, groups, i]`, serialized
   with no whitespace (JavaScript `JSON.stringify`). Blocks are concatenated.
8. **Characters.** Bytes at or above `256 - (256 mod alphabetSize)` are skipped
   to avoid modulo bias; other bytes select `alphabet[byte mod alphabetSize]`
   until the password has `length` characters. If the password lacks any
   selected group, it is discarded and generation continues from the next
   unused byte of the same stream.

Test vector: identity `test@example.com`, passphrase
`an unrelated set of words for testing`:

| Input | Output |
|---|---|
| Fingerprint | `coral igloo crane cedar` |
| `github.com`, version 1, 20 characters, all groups | `P]}WJFScfS=cVB57YPB9` |
| `github.com`, version 2, 20 characters, all groups | `?mt+dXWWFuB5G5):}?#%` |
| `home wifi`, version 1, 12 characters, digits | `261169021281` |

## Vault format version 2

Same as version 1 below, except:

- The envelope adds `identity` (already normalized) and has `version` 2. The
  identity is not encrypted.
- The AES-256-GCM key comes from HKDF as described above rather than directly
  from PBKDF2. Additional authenticated data is UTF-8 `EasyPwd vault format 2`.
- An entry may include `derive`: `{site, counter, length, groups}` with a
  normalized site, a counter from 1 to 1,000,000, and valid rules. Such an
  entry's `password` must be empty; the password is calculated when needed and
  never written to storage.

Version 1 vaults and backups are still accepted. They are migrated to version 2
after unlocking, once the user chooses an identity. The migration never writes
a version 1 vault.

## Vault format version 1

The envelope contains `format`, `version`, `kdf`, `salt`, `iv`, and `ciphertext`.
Only this exact schema is accepted. KDF parameters are fixed in version 1, so an
imported file cannot request an unbounded work factor.

- KDF: PBKDF2-HMAC-SHA-256, 600,000 iterations.
- Salt: 16 cryptographically random bytes per new vault.
- Encryption: AES-256-GCM with a 128-bit tag.
- Nonce: 12 fresh cryptographically random bytes per encryption.
- Additional authenticated data: UTF-8 `EasyPwd vault format 1`.
- Passphrase: Unicode NFC-normalized before key derivation, so the same
  passphrase typed with composed or decomposed characters opens the vault.
- Plaintext: UTF-8 JSON containing only an `entries` array. Each entry has
  `id`, `name`, `url`, `username`, `password`, `notes`, and optionally
  `updatedAt` (milliseconds since the Unix epoch).
- Encoding: canonical Base64 for salt, nonce, and ciphertext.
- Limits: 2 MB encrypted file, 1,000 entries, bounded fields.

The non-extractable key supports encryption and decryption only. Binary
passphrase/plaintext buffers are cleared where practical; JavaScript strings
and browser internals cannot be reliably wiped. PBKDF2 is browser-native, but
is not memory-hard. Any future KDF change must use an explicit version/migration,
not silently reinterpret an existing vault.

All credential fields are encrypted together. The envelope reveals its format,
KDF configuration, and approximate content size. No plaintext credential index
is persisted.

## Lifecycle and persistence

The vault page owns the unlocked session. No key is stored in local or session
storage, and no key/credential messages are sent to the background worker.
The toolbar popup can send `easypwd:lookup` with the current site to an open,
unlocked vault page. The vault page answers only messages whose sender is this
extension, not a tab, and the `popup.html` URL. It replies with the matching
logins' usernames, passwords, and current 2FA codes, plus a generated password
suggestion for the site. A locked page does not reply. Answering counts as
activity for auto-lock. If no page answers, the popup can unlock the vault
itself; that session lives only in the popup's memory and ends when it closes.
Manual lock removes application references and clears secret-bearing DOM fields.
The page locks after a user-selected period (1, 5, 15, or 30 minutes; default
5) without trusted user activity. This setting is stored unencrypted. Suspended
timers are supplemented by expiry checks on resume and protected actions.
Closing, reloading, or browser restart requires unlocking again.

Writes encrypt first, then use a same-origin Web Lock and compare the previous
encrypted snapshot before replacing the single storage item. A rejected write
leaves the editor available for retry and does not update the in-memory saved
snapshot. External changes lock other open vault pages. A lock cancels pending
crypto operations before they can start a storage write; an already-started
storage write can finish, but must not reopen the locked page.

No crash-durability guarantee is made for Chrome storage. Explicit encrypted
backups are required. Restore checks the schema, authentication tag, and
decrypted entry structure before replacement. It is not a merge operation.

Changing the master passphrase re-encrypts the vault with a new random salt and
key after verifying the current passphrase. Because generated passwords depend
on the passphrase, generated entries are first converted to saved entries that
contain their current password. Older backups are unaffected.
Deleting the vault removes the single storage item; it does not touch backups.

Chrome CSV import reads a user-selected, unencrypted file in the vault page
only. The file is not stored or uploaded; users should delete it afterwards.

The extension restricts local storage to trusted extension contexts and sets
`connect-src 'none'`. It uses DOM text nodes, not injected credential HTML.
There are no host permissions, persistent content scripts, remote assets, or
analytics.

## Clipboard clearing

After a password, previous password, 2FA code, or generated password is copied,
the page sends `easypwd:copied` (no content) to the background worker. The worker
accepts it only from this extension's own pages, then sets an alarm for the
user-selected delay (30, 60, or 120 seconds, or off; default 30). Each new copy
restarts the delay. When the alarm fires, the worker opens `offscreen.html`,
which replaces the clipboard with empty text, and closes it. Usernames and
websites are not cleared. Without `clipboardRead`, EasyPwd can't tell whether the
clipboard still holds its copy, so it clears it regardless. Clipboard history
managers, other apps that read the clipboard during the delay, and a browser that
exits before the alarm are out of scope.

## Filling pages

`activeTab` gives the popup the current tab's URL and temporary access to it
only after the user clicks the toolbar icon or presses its shortcut. **Fill**
re-reads the tab, refuses if its host has changed, and uses `scripting` to run
one self-contained function in the top frame. The function sets the visible
password field(s) of the first login form, and the username field before it,
dispatching `input` and `change` events. It returns only which fields it
filled. The page (and any script on it) can read filled values, exactly as if
the user had typed them, so fill only on sites you trust. Matching uses the
generated-password site or the saved URL's host: a login for `example.com`
matches `example.com` and its subdomains, and the other way round. Plain
`http:` pages are flagged as not secure.

## Matching site rules

**Match site rules** runs only when clicked, through the same `activeTab` +
`scripting` path as Fill (host re-check, top frame). The injected function
returns visible text near password fields and lines that mention password
requirements (capped at 4,000 characters), plus the fields' `minlength` and
`maxlength`. It reads no field values. If Chrome's built-in Prompt API
(`LanguageModel`, Gemini Nano) reports the model as available, the text is sent
to that on-device model with a JSON schema; the answer is treated as untrusted
and only mapped to a length of 8–64 and a non-empty set of character groups.
Passwords, the passphrase, and vault data are never given to the model. Chrome
downloads and runs the model itself; EasyPwd makes no network requests and
needs no extra permission. Otherwise, or if the model fails or takes over 30
seconds, a small rule-based parser is used. A hostile page can at most choose
weaker-but-valid rules (for example 8 characters, no symbols), so the popup
shows the rules it applied before you fill or save.

## Fake-site warning

When the popup has no login for the current host, `lookalikeOf` compares the
host with the sites of saved logins: the same name on another domain, the name
as a subdomain or hyphenated part (`paypal.com.evil.net`, `paypal-login.com`),
common character swaps (`rn`→`m`, `1`→`l`, `0`→`o`), a small edit distance, and
punycode whose plain letters fit the name. It runs locally on data already in
the lookup. It can't detect every phishing page (a completely different
domain is not flagged) and may flag a legitimate sister domain, so it warns and
never blocks.

## Plain-language search

Search phrases are parsed locally into filters (2FA, no username, weak, reused,
old, generated, saved, notes) and words. When Chrome's built-in model reports
`available` and a multi-word search finds nothing, pressing Enter sends only
the typed query to the on-device model, which returns words and filter names
under a JSON schema; unknown filters are dropped. Vault entries, passwords,
and notes are matched in the page and are never given to the model.

## Two-factor codes

Logins may have an `otp` object `{ secret, digits, period, algorithm }`:
an RFC 4648 base32 secret of 16–256 characters, 6–8 digits, a 10–300 second
period, and `SHA1`, `SHA256`, or `SHA512`. Codes follow RFC 6238 (TOTP) and are
tested against its published vectors. Secrets come from a pasted setup key, an
`otpauth://totp/` link, or a QR image decoded locally with the browser's
`BarcodeDetector`; HOTP is rejected. The secret is encrypted with the rest of
the vault. Storing it beside the password means anyone with the master
passphrase and the vault, or a backup, has both factors. Vaults and backups
that contain `otp` cannot be opened by EasyPwd versions before 0.3.0.
