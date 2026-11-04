# Guard Service

`FolderLock.Service.exe` is an optional background Windows service
(`FolderLockGuard`) that keeps ACL-locked folders locked even if the desktop app
is not running or is tampered with.

## How it works

- The desktop app publishes the list of currently ACL-locked folders to a
  machine-wide watchlist file:
  - `%PROGRAMDATA%\FolderLock\watchlist.json` (normal), or
  - `<app>\data\watchlist.json` (portable mode).
- The service runs as **`NT AUTHORITY\LocalService`** (a low-privilege account),
  wakes every 10 seconds, and re-applies the deny-everyone lock to any folder in
  the watchlist whose lock was removed. If it lacks `WRITE_DAC` on a folder, it
  logs a warning and skips that entry instead of aborting the pass.
- It is configured with automatic restart-on-failure.

The watchlist contains **only paths**, never passwords or keys.

## Install / uninstall

From the app: **Tools → Install guard service (admin)** (and *Uninstall*).
This launches an elevated helper.

Or from PowerShell **as administrator**:

```powershell
.\installer\install-service.ps1
.\installer\uninstall-service.ps1
```

## Notes

- The service is installed **per machine** (into `%ProgramFiles%\FolderLock`).
  Normal users have read-only access to the program directory; the machine-wide
  data folder `%ProgramData%\FolderLock` is user-writable so the app can maintain
  the watchlist. Installing requires administrator rights; the desktop app
  itself does not.
- Signature checking is **warn mode** by default: the service verifies its own
  Authenticode signature and writes the result to
  `%ProgramData%\FolderLock\service.log`, but still starts. Set
  `FOLDERLOCK_REQUIRE_SIGNATURE=1` (or `RequireServiceSignature: true` in
  `service-settings.json`) to refuse unsigned or wrongly-signed binaries. The
  currently published binaries are **unsigned**.
- The service only manages **ACL** locks. AES-encrypted folders are handled by
  the app, since re-locking them needs the password.
- To stop autostart, set the service to manual or uninstall it.
