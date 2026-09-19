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

```
magic "FLVLT1" (6 bytes)
version u8
flags u8          (bit0 = has recovery code, bit1 = payload is gzip-compressed)
iterations i32 LE
saltPassword  (16)
saltRecovery  (16)
wrappedByPassword  (12 nonce + 32 ct + 16 tag = 60)
wrappedByRecovery  (60)
payload = sequence of chunks:
    plaintextLen i32 LE   (0 = end)
    nonce (12)
    ciphertext (plaintextLen)
    tag (16)
```

- **DEK**: 32 random bytes.
- **KEK**: `PBKDF2(password|recoveryCode, salt, iterations, 32)`.
- `wrappedBy*` = AES-256-GCM(KEK, DEK).
- Each payload chunk is AES-256-GCM with the DEK; the chunk index is used as AAD
  to prevent reordering.
- The payload is a simple stream of entries (type, relative path, timestamp,
  size, content). Relative paths are validated to prevent traversal.

## Compression

Payloads are gzip-compressed by default before encryption (flagged in the
header). This reduces container size for compressible data at a small CPU cost.
Old containers without the flag still decrypt fine.

## Verify & salvage

**Tools → Verify / salvage vault**:

1. Reads the header and reports version, iteration count, whether a recovery code
   is present, and the container size.
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
