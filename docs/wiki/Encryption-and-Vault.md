# Encryption & Vault

## Overview

When you add a folder with **Use AES-256 encryption** enabled, locking it
produces a single container file next to the original folder:

```
<parent>\<FolderName>.flvault
```

The original folder is securely wiped and removed. Unlocking decrypts the
container back to the original path and deletes the container.

## Container format

New containers are written in **format v3**:

- The header is duplicated into two independent blocks (**A/B**), each carrying
  the same information. Either block is enough to open the container, so a
  damaged header write cannot make the whole file unreadable.
- The envelope wraps one data key with **1–8 key slots**. Each slot wraps the
  same DEK with a different secret: password, recovery code, optional emergency
  password, and local auto-unlock (Windows DPAPI).
- An authenticated end block records the chunk count and plaintext byte total,
  so metadata tampering and truncation are detected.

Legacy **v2** containers are read-only and can be upgraded in place to v3 (the
original file is kept as `.bak`). Legacy **v1** containers are read-only.

### v2 legacy layout

The byte layout below describes legacy **v2** containers and is kept for
reference:

```
magic "FLVLT1" (6 bytes)
version u8         (2 = legacy v2, 1 = legacy v1, both read-only)
flags u8           (bit0 = has recovery code, bit1 = payload is gzip-compressed)
iterations i32 LE
saltPassword  (16)
saltRecovery  (16)
wrappedByPassword  (12 nonce + 32 ct + 16 tag = 60)
wrappedByRecovery  (60)
headerMac     (32)  HMAC-SHA256 keyed by the DEK over the header bytes above
payload = sequence of 64 KiB chunks:
    plaintextLen i32 LE   (1..65536)
    nonce (12)
    ciphertext (plaintextLen)
    tag (16)
end block:
    marker i32 LE  (-1)
    nonce (12)
    ciphertext (16)  = chunk count (i64) + total plaintext bytes (i64)
    tag (16)
```

- **DEK**: 32 random bytes.
- **KEK**: `PBKDF2(password|recoveryCode, salt, iterations, 32)`.
- `wrappedBy*` = AES-256-GCM(KEK, DEK).
- Each payload chunk is AES-256-GCM with the DEK; the chunk index is used as AAD
  to prevent reordering.
- The 32-byte header MAC (keyed by the DEK) covers the flags and KDF parameters,
  so metadata tampering is detected. Only v2 containers have this single header
  MAC; v3 replaces it with the A/B header blocks and per-slot wrapping described
  above.
- The authenticated end block records the chunk count and plaintext byte total;
  a missing or mismatched end block means the container was truncated or tampered
  with. v2 and v3 containers have it.
- The payload is a simple stream of entries (type, relative path, timestamp,
  size, content). Relative paths are validated to prevent traversal.

**Legacy v1** containers have no header MAC and end with a 4-byte zero length
instead of the authenticated end block. They remain readable, are never written
any more, and are **not migrated automatically**; header authentication and
truncation detection apply to v2 and v3 only.

## Compression

Payloads are gzip-compressed by default before encryption (flagged in the
header). This reduces container size for compressible data at a small CPU cost.
Old containers without the flag still decrypt fine.

## Verify & salvage

**Tools → Verify / salvage vault**:

1. Reads the header and reports version, iteration count, whether a recovery code
   is present, whether the payload is compressed, and the container size.
2. Verifies the container decrypts with your password/recovery code.
3. If verification fails, offers to **salvage** — best-effort export of
   recoverable content to a folder you choose. Salvage is limited because GCM is
   all-or-nothing per chunk; recovery typically stops at the first damaged chunk.

## Space requirements

Encrypting needs free space roughly equal to the folder size (the container and
source briefly coexist). VaultLock pre-checks free disk space and aborts early
with a clear message if it is insufficient.

## Progress & cancellation

Encryption/decryption run in the background with a progress overlay. Cancel
leaves the source intact for lock, and keeps the container intact for unlock
(partial output is removed).
