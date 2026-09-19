# Installation

## Requirements

- Windows 10 1809+ or Windows 11 (x64).
- [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)
  (the releases are framework-dependent).
- Administrator rights only for the optional **guard service** and for
  registering a per-machine shell extension.

## From a release (recommended)

1. Open [Releases](https://github.com/oMrCat/VaultLock/releases).
2. Pick a build:
   - **`v1.0.0`** — full build, includes the optional Windows Hello unlock gate
     (larger single file, ~35 MB).
   - **`v1.0.0-lite`** — no Windows Hello (smaller, ~9 MB). All other features
     are identical.
3. Download the `.zip`, extract it somewhere (e.g. `C:\Tools\VaultLock`).
4. Run `FolderLock.App.exe`.

The zip contains:

| File | Purpose |
|---|---|
| `FolderLock.App.exe` | The desktop app (tray-resident) |
| `FolderLock.Service.exe` | Optional background guard service |

> Because the binaries are unsigned, Windows SmartScreen may warn on first run.
> Choose *More info → Run anyway*, or build and code-sign it yourself.

## First run

- The app minimizes to the tray when closed.
- Open **Tools (⋯)** for themes, language, auto-lock, the panic hotkey, logs,
  recovery-kit export/import and the guard service.
- **Tools → Register context menu** adds right-click entries in Explorer.

## Portable mode

Create an empty file named `portable.flag` next to `FolderLock.App.exe`. All
data (database, encryption key, settings, watchlist) is then stored in a
`data\` folder beside the app instead of `%APPDATA%` / `%PROGRAMDATA%`.

## Uninstall

The app is portable-by-copy. To remove it:

1. **Tools → Uninstall guard service** (if you installed it).
2. **Tools → Remove context menu** and turn off *Start with Windows*.
3. Delete the extracted folder.

Your data lives in `%APPDATA%\FolderLock` (or the portable `data\` folder) and
`%PROGRAMDATA%\FolderLock` (guard watchlist). Delete those only if you also want
to drop the folder list and lock metadata. **Encrypted vaults (`.flvault`) are
not affected** — keep them and your password/recovery code.
