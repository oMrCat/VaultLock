# Recovery & Backup

## Recovery channels (v3 vaults)

New vaults use the **v3** container format: an A/B header with up to eight key
slots. Each slot wraps the same data key with a different secret, so any one of
these opens the vault independently:

| Channel | Where the secret lives | Notes |
| --- | --- | --- |
| Password | vault header | required, always present |
| Recovery code | vault header | shown at creation |
| Emergency password | vault header | optional, managed in the app |
| Local unlock (DPAPI) | local database | machine + Windows user bound |

**Forgot password?** in the unlock dialog opens a wizard that tries each
available channel and reports **channel missing / wrong key / success**. After
success you set a new password; the data itself is not re-encrypted.

v2 vaults are read-only and can be upgraded in place to v3 (the original file is
kept as a `.bak`).

## Recovery codes

Every AES-encrypted folder gets a **recovery code** when it is added. It is
shown once; save it immediately. It can unlock the vault if you forget the
password.

- Format: Crockford Base32 groups, e.g. `8W5V-SP3F-ACKA-198Y-CZJK-9TAR-C8MY-16GW`.
- Normalization tolerates case, separators, and ambiguous characters
  (`I/L → 1`, `O → 0`).
- Stored locally protected by Windows DPAPI. The dialog can print the code and
  clears the clipboard after copying.
- The code can be viewed again without the password for **7 days** after it was
  created or last revealed; afterwards the main password is required.
- If the code has not been confirmed as backed up for **30 days**, the status
  bar shows a reminder.

> If both the password **and** the recovery code are lost, an encrypted vault is
> unrecoverable. There is no backdoor. The wizard states this explicitly when
> every channel has failed.

## Password hints

A hint can be attached to an encrypted folder. It is encrypted with DPAPI and
stored only in the local database — never inside the `.flvault` file — and is
shown in the unlock prompt on the same Windows account/machine.

## Changing a password

**Change password** re-encrypts nothing by itself: it updates the stored password
hash. Because the vault wraps its key with the password at lock time, you cannot
change the password of an encrypted folder while it is **locked** — unlock it
first.

## Recovery kit (`.flkit`)

**Tools → Export recovery kit** writes a password-protected file containing the
folder list, password hashes and recovery codes (decrypted and re-protected by
the kit passphrase). Use it to restore your setup on a new machine or after
reinstalling Windows.

**Tools → Import recovery kit** merges entries that are not already present,
re-protecting recovery codes with the current machine's DPAPI. Existing entries
are left untouched.

## Backup recommendations

- Keep an offline copy of each recovery code, or a recent `.flkit` export.
- Keep your `.flvault` files together with the password/recovery code.
- Consider full-disk encryption in addition, since secure deletion on SSDs is
  best-effort.
- The SQLite database (`%APPDATA%\FolderLock\folderlock.db`) is encrypted with a
  DPAPI-protected key; copying it to another Windows account/machine will not
  open it.
