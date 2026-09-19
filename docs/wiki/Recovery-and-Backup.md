# Recovery & Backup

## Recovery codes

Every AES-encrypted folder gets a **recovery code** when it is added. It is
shown once; save it immediately. It can unlock the vault if you forget the
password.

- Format: Crockford Base32 groups, e.g. `8W5V-SP3F-ACKA-198Y-CZJK-9TAR-C8MY-16GW`.
- Normalization tolerates case, separators, and ambiguous characters
  (`I/L → 1`, `O → 0`).
- Stored locally protected by Windows DPAPI; you can view it later from
  **View recovery code** on a folder you still own.

> If both the password **and** the recovery code are lost, an encrypted vault is
> unrecoverable. There is no backdoor.

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
