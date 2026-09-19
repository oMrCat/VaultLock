# VaultLock Wiki

**VaultLock** is a modern Windows app to password-protect folders. It offers fast
NTFS **ACL locks** and optional real **AES-256-GCM encrypted vaults**, plus
secure deletion, trace cleaning, auto-lock, recovery codes and a background
guard service, in a clean Fluent (Windows 11 style) UI. English and 简体中文.

> Repo: <https://github.com/oMrCat/VaultLock>
> Product **VaultLock**, internal solution/namespace `FolderLock`.

[中文文档](中文文档) · [Releases](https://github.com/oMrCat/VaultLock/releases) · [README](https://github.com/oMrCat/VaultLock#readme)

## Contents

- [Installation](Installation)
- [Usage](Usage)
- [Security Model](Security-Model)
- [Encryption & Vault](Encryption-and-Vault)
- [Auto-Lock & Hotkey](Auto-Lock-and-Hotkey)
- [Recovery & Backup](Recovery-and-Backup)
- [Guard Service](Guard-Service)
- [Building from Source](Building-from-Source)
- [FAQ](FAQ)
- [中文文档](中文文档)

## Quick start

1. Download a build from [Releases](https://github.com/oMrCat/VaultLock/releases):
   - `v1.0.0` — full build with the optional Windows Hello unlock (~35 MB).
   - `v1.0.0-lite` — smaller build, no Windows Hello (~9 MB).
2. Extract and run `FolderLock.App.exe` (requires the .NET 8 Desktop Runtime).
3. Add a folder, set a password, click **Lock**.
