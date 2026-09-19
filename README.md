# VaultLock

**VaultLock** (internal project name: `FolderLock`) is a modern Windows app for
password-protecting folders. It combines fast NTFS permission locking with an
optional real **AES-256-GCM encrypted vault**, and adds secure file wiping,
trace cleaning, auto-lock, recovery codes and a background guard service — all
behind a clean Fluent (Windows 11 style) UI.

> The Windows project/namespace is `FolderLock` for historical reasons; the
> product is published as **VaultLock**.

[中文文档 / Chinese README](README.zh-CN.md) · [Docs](docs/wiki/Home.md) · [Wiki](https://github.com/oMrCat/VaultLock/wiki)

---

## Screenshot

![VaultLock main window](docs/images/main-window.png)

---

## Features

### Locking
- **ACL lock** — backs up the folder's original security descriptor (SDDL),
  applies a deny-everyone DACL and hides the folder. Restoring is exact and
  reversible. Instant, no data movement.
- **AES-256-GCM vault (optional)** — encrypts the whole folder into a single
  `.flvault` container with an envelope scheme (random DEK wrapped by the
  password and by a recovery code). Protects against admin access and offline
  copying. Optional GZip compression before encryption.
- **Dangerous-path guard** — refuses to lock drive roots, `Windows`,
  `System32`, `Program Files*`, `ProgramData`, profile roots, Desktop,
  Documents, etc.
- **Disk space pre-check** before encrypting/decrypting.

### Security
- Passwords stored as `PBKDF2-HMAC-SHA256`, 210,000 iterations, random salt,
  constant-time comparison. Never stored in plaintext.
- **Recovery code** (Crockford Base32) to unlock an encrypted vault if the
  password is forgotten; protected locally with Windows DPAPI and exportable.
- **Memory hygiene** — passwords/recovery codes are held in a zeroing `Secret`
  buffer and clipboard is cleared after use.
- **Failed-attempt throttling** — escalating lockouts after repeated wrong
  passwords (5→30s, 7→5min, 10→30min).
- **Audit log** — every add/lock/unlock/change/failed attempt/auto-relock is
  recorded and exportable to CSV.
- **Encrypted database** — the SQLite store uses SQLCipher with a random key
  protected by DPAPI; existing plaintext databases are migrated automatically.
- **Trace cleaning** — after encryption, source files are overwritten with
  random data and the folder is removed; Recent shortcuts, jump lists, common
  MRU registry entries and thumbnail caches are cleaned.
- **Self-integrity check** on startup.

### Automation
- **Auto-lock** on screen lock / sign-out (Windows session notifications),
  when idle, and after a temporary unlock timeout.
- **Global panic hotkey** `Ctrl+Alt+L` — locks everything, clears the clipboard
  and minimizes.
- **Tray resident** with notifications; optional run at startup.
- **Guard service** (`FolderLockGuard`) — a Windows service that continuously
  re-applies locks if tampered with.

### Data safety
- **Vault verify & salvage** — inspect a container, verify it decrypts, and
  salvage recoverable content from a corrupted vault.
- **Export / import recovery kit** — password-protected `.flkit` backup of the
  folder list, password hashes and recovery codes, portable across machines.
- **Portable mode** — drop a `portable.flag` next to the executable to keep all
  data (database, key, settings, watchlist) beside the app.

### Experience
- Fluent (Windows 11) UI with light/dark/system themes, sidebar filters, live
  search, sortable list, detail pane and an empty state.
- Password strength meter and generator.
- **English / 简体中文** UI.
- Right-click Explorer integration and single-instance command forwarding.

---

## Requirements

- Windows 10 1809+ or Windows 11 (x64).
- [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) for
  framework-dependent builds.
- To build: .NET 8 SDK.

## Getting started

```powershell
# run from source
dotnet run --project src\FolderLock.App

# tests
dotnet test
```

### Publish

```powershell
# full build (includes Windows Hello), ~35 MB single file
.\installer\publish.ps1

# small build without Windows Hello, ~9 MB
.\installer\publish.ps1 -NoHello

# optionally code-sign
.\installer\publish.ps1 -CertThumbprint <thumbprint>
```

Output: `src\FolderLock.App\bin\Release\<tfm>\publish\win-x64\`
(contains `FolderLock.App.exe` and `FolderLock.Service.exe`).

### Installer

`installer\FolderLock.iss` is an [Inno Setup](https://jrsoftware.org/isinfo.php)
script. Publish first, then compile the script.

### Guard service (optional, admin)

```powershell
.\installer\install-service.ps1
.\installer\uninstall-service.ps1
```

Or use *Tools → Install guard service* in the app.

---

## Usage

1. Launch the app and click **Add folder** (or drag folders in).
2. Set a password. Tick **AES-256** for strong encryption; save the recovery
   code it shows.
3. Select the folder and click **Lock** / **Unlock**. Encrypted operations show
   a progress overlay and can be cancelled.
4. Use *Tools* (⋯) for themes, language, auto-lock, the panic hotkey, logs,
   vault verify/salvage, recovery-kit export/import and the guard service.

---

## Project layout

| Project | Description |
|---|---|
| `src/FolderLock.Core` | Crypto, vault, ACL, cleanup, storage, services |
| `src/FolderLock.App` | WPF (Fluent) desktop app |
| `src/FolderLock.Service` | Background guard Windows service |
| `tests/FolderLock.Core.Tests` | xUnit test suite |
| `installer/` | Publish, service and Inno Setup scripts |

## Testing

```powershell
dotnet test
```

Over 130 unit tests cover password hashing, the ACL locker (against real
temporary folders), vault round-trips/corruption, purge, trace cleaning,
throttling, audit, SQLCipher encryption and migration, updater versioning and
overlay logic.

---

## Security model & honest limitations

- **ACL lock** blocks other standard users on the same machine and casual
  access; it does **not** stop administrators, SYSTEM, or Safe Mode.
- **AES vault** protects against offline access and admins, but not against
  malware running as you while unlocked, and not against a cold-boot attacker.
- Secure deletion is best-effort: on SSDs, TRIM/wear-levelling, the page file,
  and the Windows Search index may retain copies. Use full-disk encryption for
  strong guarantees.
- Forgetting an encrypted folder's password means only the recovery code can
  restore it — keep it safe.

---

## License

[MIT](LICENSE) © 2026 oMrCat
