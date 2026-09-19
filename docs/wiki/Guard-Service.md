# Guard Service

`FolderLock.Service.exe` is an optional background Windows service
(`FolderLockGuard`) that keeps ACL-locked folders locked even if the desktop app
is not running or is tampered with.

## How it works

- The desktop app publishes the list of currently ACL-locked folders to a
  machine-wide watchlist file:
  - `%PROGRAMDATA%\FolderLock\watchlist.json` (normal), or
  - `<app>\data\watchlist.json` (portable mode).
- The service runs as **LOCAL SYSTEM**, wakes every 10 seconds, and re-applies
  the deny-everyone lock to any folder in the watchlist whose lock was removed.
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

- Installing requires administrator rights; the desktop app itself does not.
- The service only manages **ACL** locks. AES-encrypted folders are handled by
  the app, since re-locking them needs the password.
- To stop autostart, set the service to manual or uninstall it.
