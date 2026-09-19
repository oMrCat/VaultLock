# Building from Source

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Windows 10/11

```powershell
git clone https://github.com/oMrCat/VaultLock.git
cd VaultLock

dotnet build
dotnet test
dotnet run --project src\FolderLock.App
```

## Projects

| Project | Target | Description |
|---|---|---|
| `src/FolderLock.Core` | `net8.0-windows` | Crypto, vault, ACL, cleanup, storage, services |
| `src/FolderLock.App` | `net8.0-windows[*]` | WPF (Fluent) desktop app |
| `src/FolderLock.Service` | `net8.0-windows` | Guard service |
| `tests/FolderLock.Core.Tests` | `net8.0-windows` | xUnit tests |

`[*]` The app targets `net8.0-windows10.0.19041.0` when Windows Hello support is
enabled (default), or `net8.0-windows` when it is disabled.

## Windows Hello switch

```powershell
# full build with Windows Hello (default)
dotnet build src\FolderLock.App\FolderLock.App.csproj

# build without Windows Hello (smaller, no WinRT)
dotnet build src\FolderLock.App\FolderLock.App.csproj -p:FolderLockHello=false
```

## Publishing

```powershell
# full build (~35 MB single file)
.\installer\publish.ps1

# small build, no Windows Hello (~9 MB)
.\installer\publish.ps1 -NoHello

# optional code signing (signtool must be on PATH)
.\installer\publish.ps1 -CertThumbprint <thumbprint>
```

Output: `src\FolderLock.App\bin\Release\<tfm>\publish\win-x64\`.

## Installer

`installer\FolderLock.iss` is an [Inno Setup](https://jrsoftware.org/isinfo.php)
script. Publish first, then compile the script with ISCC.

## Tests

The suite (>130 tests) covers password hashing, the ACL locker (against real
temporary folders), vault round-trips and corruption, secure deletion, trace
cleaning, throttling, audit, SQLCipher encryption and migration, the updater and
overlay logic.

```powershell
dotnet test
```
