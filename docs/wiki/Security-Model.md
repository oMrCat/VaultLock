# Security Model

## Two locking modes

### ACL lock
- Backs up the folder's security descriptor (SDDL), then replaces the DACL with
  a deny-everyone rule (keeping SYSTEM/Administrators out of the way via owner
  rights) and sets `Hidden` + `System` attributes.
- Unlock restores the exact original SDDL and clears the attributes.
- **Protects against:** other standard users on the same PC and casual access.
- **Does not protect against:** administrators (who can take ownership), SYSTEM,
  Safe Mode, or another OS.

### AES-256-GCM vault (optional)
- Encrypts the whole folder into a single `.flvault` file, then securely deletes
  the source.
- Envelope scheme: a random data-encryption key (DEK) is wrapped twice — by the
  password and by the recovery code — so either can unlock.
- Each 64 KiB chunk is separately AES-256-GCM authenticated; chunks are bound to
  their order via AAD.
- **Protects against:** offline access, copying the disk, and administrators.
- **Does not protect against:** malware running as you while the folder is
  unlocked, or a cold-boot/evil-maid attacker.

## Password handling

- `PBKDF2-HMAC-SHA256`, 210,000 iterations, 16-byte random salt, 32-byte output.
- Constant-time comparison. Passwords are never stored in plaintext.
- In memory, secrets live in a zeroing `Secret` buffer; the clipboard is cleared
  after copying a recovery code.

## Recovery code

- Crockford Base32, 160-bit. Wrapped locally with Windows DPAPI.
- Lets you unlock an encrypted vault if the password is forgotten. Keep it
  somewhere safe and offline.

## Failed-attempt throttling

The number of consecutive wrong passwords is tracked per folder and persisted:

| Attempts | Lockout |
|---|---|
| 5 | 30 seconds |
| 7 | 5 minutes |
| 10 | 30 minutes |

A successful unlock resets the counter.

## Audit log

Every add / lock / unlock / change-password / remove / failed attempt /
auto-relock is recorded with a timestamp and success flag. Export to CSV from the
log window.

## Encrypted database

The SQLite store uses **SQLCipher** with a random 32-byte key protected by DPAPI
(`db.key`). Existing plaintext databases are migrated automatically on first run.
Connection pooling is disabled so a keyed connection is never reused across keys.

## Trace cleaning (after AES lock)

- Source files are overwritten with random data, truncated, renamed, and deleted.
- Explorer **Recent** shortcuts and jump lists, common MRU registry keys
  (`RecentDocs`, `TypedPaths`, `RunMRU`, `ComDlg32`, …), and thumbnail/icon
  caches are cleaned for the folder.

**Honest limitations:** on SSDs, TRIM / wear-levelling, the page file, and the
Windows Search index may retain copies. Secure deletion is best-effort; use
full-disk encryption for stronger guarantees.

## Windows Hello (full build)

Optional. When enabled, a correct password is followed by a Windows Hello
verification (`UserConsentVerifier`) before the folder unlocks. It is an extra
gate, not a replacement for the password, and is bound to this device/account.
