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
  applies a deny-everyone DACL and hides the folder. Unlock re-applies the
  saved DACL; it is not a byte-for-byte rollback of every ownership/inheritance
  change, so ownership taken over by another account needs manual recovery
  (`takeown` + `icacls`). Before locking, the app pre-checks `WRITE_DAC` and
  refuses with an explicit message instead of creating a one-way lock. Instant,
  no data movement.
- **AES-256-GCM vault (optional)** — encrypts the whole folder into a single
  `.flvault` container with an envelope scheme (random DEK wrapped by **1–8 key
  slots**: password, recovery code, optional emergency password, and local
  auto-unlock via DPAPI). Protects against admin access and offline copying.
  New containers use format **v3** (A/B header blocks plus an authenticated end
  block, so a damaged header cannot make the whole container unreadable, and
  metadata tampering and truncation are detected); **v2** containers are
  read-only and can be upgraded in place to v3 (the original file is kept as
  `.bak`); **v1** containers are read-only. Optional GZip compression before
  encryption.
- **Dangerous-path guard** — refuses to lock drive roots, `Windows`,
  `System32`, `Program Files*`, `ProgramData`, profile roots, Desktop,
  Documents, etc.
- **Disk space pre-check** before encrypting/decrypting.

### Security
- Passwords stored as `PBKDF2-HMAC-SHA256`, 210,000 iterations, random salt,
  constant-time comparison. Never stored in plaintext.
- **Recovery code** (Crockford Base32) to unlock an encrypted vault if the
  password is forgotten; protected locally with Windows DPAPI, printable from
  the dialog, and the clipboard is cleared after copying. It can be viewed
  again without the password for **7 days** after creation or last viewing;
  after that the main password is required. If it has not been confirmed as
  backed up for **30 days**, the status bar shows a reminder.
- **Multi-channel recovery** — besides the password, the recovery code, the
  emergency password and local auto-unlock (DPAPI) can each unlock independently;
  the **Forgot password** wizard tries every available channel and reports
  **channel missing / wrong key / success**.
- **Password hint** — DPAPI-protected and stored only in the local database,
  never written into the `.flvault` container; shown in the unlock prompt on the
  same Windows account/machine.
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
- **Self-integrity check** — the app and the guard service verify their own
  Authenticode signature, and the signer identity when expected publishers are
  pinned (`FOLDERLOCK_EXPECTED_PUBLISHERS` or `expected-publishers.txt`).
- **Signed updates** — the updater only accepts HTTPS, verifies the payload
  SHA-256 hash and checks the Authenticode signature before applying.

### Automation
- **Auto-lock** on screen lock / sign-out (Windows session notifications),
  when idle, and after a temporary unlock timeout. If password caching is
  turned off, an automatic re-lock is impossible without the password, so the
  app asks you to lock manually instead of failing silently.
- **Global panic hotkey** `Ctrl+Alt+L` — locks everything, clears the clipboard
  and minimizes.
- **Tray resident** with notifications; optional run at startup.
- **Guard service** (`FolderLockGuard`) — a Windows service running as
  `NT AUTHORITY\LocalService` that continuously re-applies locks if tampered
  with. Signature checking is in **warn mode** by default (log only); set
  `FOLDERLOCK_REQUIRE_SIGNATURE=1` (or `RequireServiceSignature: true` in
  `%ProgramData%\FolderLock\service-settings.json`) to refuse unsigned or
  wrongly-signed binaries.

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
- Explorer right-click cascade menus written to HKCU by default, with
  multi-selection: folders get lock / unlock / add to list / remove from list /
  open, `.flvault` files get verify / decrypt / salvage / open. Single-instance
  command forwarding.

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

# optionally code-sign (signtool must be on PATH)
.\installer\publish.ps1 -Sign -Thumbprint <thumbprint>
```

Output: `artifacts\publish\win-x64\` (contains `FolderLock.App.exe` and
`FolderLock.Service.exe`). Both the Inno Setup script and `install-service.ps1`
read from that fixed path.

### Installer

`installer\FolderLock.iss` is an [Inno Setup](https://jrsoftware.org/isinfo.php)
script. Publish first, then compile the script.

The installer is per-machine (`{autopf}`, requires admin): the program directory
is read-only for normal users and data lives in `%ProgramData%\FolderLock`.

> The installers currently attached to GitHub Releases are **unsigned**. Windows
> will show "unknown publisher", and the guard service runs in **warn mode**
> (signature problems are logged, not enforced). This is intentional for local
> validation; for real distribution, sign with a trusted certificate and set
> `FOLDERLOCK_REQUIRE_SIGNATURE=1`.

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

238 unit tests cover password hashing, the ACL locker (against real temporary
folders, including the `WRITE_DAC` pre-check and OI|CI inheritance behaviour),
vault round-trips/corruption (v1 read compatibility, v2 in-place upgrade and v3
authentication), purge, trace cleaning,
throttling, audit, SQLCipher encryption and migration, updater versioning,
HTTPS/hash/signature validation, and overlay logic.

---

## Security model & honest limitations

- **ACL lock** blocks other standard users on the same machine and casual
  access; it does **not** stop administrators, SYSTEM, or Safe Mode. An
  administrator can also take ownership and re-grant access; recovery after
  that requires `takeown` + `icacls` — the saved SDDL is re-applied on unlock,
  but ownership is not silently reverted.
- **AES vault** protects against offline access and admins, but not against
  malware running as you while unlocked, and not against a cold-boot attacker.
  Only v3 containers authenticate their metadata and detect truncation; legacy
  v2 containers are read-only but can be upgraded in place to v3, and v1
  containers are read-only.
- **Guard service signature checks** default to warn mode: a replaced
  `FolderLock.Service.exe` is logged but still runs. Set
  `FOLDERLOCK_REQUIRE_SIGNATURE=1` with a trusted signing certificate to get
  real enforcement.
- Secure deletion is best-effort: on SSDs, TRIM/wear-levelling, the page file,
  and the Windows Search index may retain copies. Use full-disk encryption for
  strong guarantees.
- If you forget an encrypted folder's password, only another recovery channel
  can restore it — the recovery code, the emergency password, or local
  auto-unlock on the same machine. Keep the recovery code safe.

---

## License

[MIT](LICENSE) © 2026 oMrCat
