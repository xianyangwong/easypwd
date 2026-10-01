# Contributing to EasyPwd

Keep changes small and preserve the offline, minimal-permission design. All UI
copy, documentation, errors, and examples must be in English. Credential values
may contain any supported Unicode text.

Before opening a pull request, run:

```sh
npm test
npm run check
npm run build
```

Include the user-visible behavior, tradeoffs, and verification performed. New
permissions, dependencies, crypto-format changes, and network access need an
explicit justification. Never include real credentials or personal vault files.

The generated-password derivation in `SECURITY.md` is frozen. Any change that
alters a pinned test vector would silently change users' passwords; it needs a
new format version and a migration, never an edit to the existing vectors.

## Manual acceptance checks

Use a disposable Chrome profile and fake credentials.

1. Load `extension/` unpacked and open it from the toolbar.
2. Create a vault with an email and passphrase. Note the fingerprint. Type
   `github.com` in search and press Enter; save it. In a second Chrome profile,
   create a vault with the same email and passphrase: the fingerprint and the
   `github.com` password must match.
3. Rotate a generated password; the previous version must stay visible. Edit
   its length and character groups and confirm the change warning. Add a saved
   login, edit it, search for it, and use the Generator page.
4. Reveal/hide and copy the password. Confirm that copying is explicit.
5. Lock and check that inputs and credential names disappear. A wrong
   passphrase must fail with a clear message, keep the field selected for
   retyping, and leave the vault unchanged. Caps Lock should show a warning.
6. Close/reopen the vault page and confirm that unlocking is required.
7. Set auto-lock to 1 minute and leave the unlocked page idle, including in a background
   tab. Returning must show a locked vault before a protected action succeeds.
8. Export a backup, edit the local credential, then restore the backup.
   Confirm replacement and unlock to verify the original credential returns.
9. Try a wrong backup passphrase, malformed JSON, an altered ciphertext, and
   an oversized file. The current vault must remain usable.
10. Open two vault tabs. Save a change in one; the other should lock. It must
    not overwrite the new version from a stale snapshot.
11. Change the master passphrase. The old passphrase must fail and the new one
    must unlock; an older backup must still restore with its own passphrase.
    Generated logins must become saved logins with the same passwords, and a
    new fingerprint must be shown.
12. Load a version 0.1 (format 1) vault or backup. Unlocking or restoring must
    ask for an email or name, upgrade it, and keep every login.
13. Check a narrow window and keyboard navigation. No horizontal overflow,
    unlabeled inputs, or hidden plaintext passwords should remain after locking.
14. Import a Chrome password CSV (with quoted commas and a non-web URL). Re-import
    it and confirm duplicates are skipped.
15. Use **Forgot passphrase?** and type `DELETE`. Other open tabs must lock and
    show the create screen.
16. Check light and dark mode.
17. Inspect extension-page network activity: no application network requests.

Chrome extension APIs and browser clipboard behavior need browser checks;
passing the core Node tests alone is not evidence that these integrations work.
