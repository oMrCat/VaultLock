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
.\installer\publish.ps1 -Sign -Thumbprint <thumbprint>
```

Output: `src\FolderLock.App\bin\Release\<tfm>\publish\win-x64\`.

## 代码签名

`FolderLock.Service.exe` 启动时会校验自身 Authenticode 签名，并把结论写入
`%ProgramData%\FolderLock\service.log`。默认是**警告模式**（只记录、不阻止启动），
正式发布应签名并切换到**严格模式**，详见下文“警告模式与严格模式”。

### 证书选择

- **OV**：便宜、签发快，但新证书仍需累积 SmartScreen 信誉，早期下载可能提示“未知发布者”。
- **EV**：通常需要硬件令牌/云 HSM，SmartScreen 立即受信，面向公众分发时选它。
- 证书有效期通常 1 年，**务必带 RFC3161 时间戳**；否则证书一过期，已发布的签名也会一起失效。

### 签名与发布

```powershell
# 证书已导入 CurrentUser\My（按指纹签名）
.\installer\sign.ps1 -Thumbprint <指纹> -ExpectedPublisher "CN=..., O=..."

# 或 PFX 文件 + 环境变量里的密码
$env:CODE_SIGN_PFX_PASSWORD = "***"
.\installer\publish.ps1 -Sign -PfxPath .\cert\codesign.pfx -ExpectedPublisher "CN=..., O=..."

# 只打印 signtool 命令，不实际签名
.\installer\sign.ps1 -Thumbprint <指纹> -DryRun
```

`sign.ps1` 执行 `signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256`，
随后立即用 `Get-AuthenticodeSignature` 校验**状态与签名者主题**；任一步失败都以非零码退出，
`publish.ps1 -Sign` 因此会直接中止，不会产出签名错误的包。

### 安装包

`FolderLock.iss` 采用**发布前预签名**：`publish.ps1 -Sign` 先把 exe 签好，Inno 原样打包，
签名在解包后依然有效；安装包本身再用 `sign.ps1 -InstallerFiles` 追加签名。
脚本里保留了注释形式的内置 `SignTool` 模板，需要连卸载器一起签时解开注释即可。

### 发布者固定校验

服务、主程序与更新器现在不只看“签名有效”，还要求签名者主题匹配预期发布者：

- 环境变量 `FOLDERLOCK_EXPECTED_PUBLISHERS`（分号分隔多个），或
- `%ProgramData%\FolderLock\expected-publishers.txt`（每行一个，`#` 开头为注释）。

未配置时退回“只校验签名有效性”，服务会写一条警告日志。这样任何有效证书签出的恶意 exe
都无法冒充发布者。

### 警告模式与严格模式

服务启动时的签名校验有两种模式，由配置项 `RequireServiceSignature` 决定（默认 `false`）：

| 模式 | 配置 | 未签名 / 签名无效 / 发布者不符 |
|---|---|---|
| 警告（默认） | `RequireServiceSignature = false` | 写 `[警告]` 日志后**照常启动** |
| 严格 | `RequireServiceSignature = true` | 写 `[错误]` 日志并**拒绝启动**（SCM 报启动失败） |

任一种模式都会在 `service.log` 里写明“当前模式：警告/严格”，并记录校验结论。

切换方式（两者冲突时环境变量优先）：

```powershell
# 方式一：环境变量（服务管理器里设置，重启服务生效）
FOLDERLOCK_REQUIRE_SIGNATURE=1     # 严格
FOLDERLOCK_REQUIRE_SIGNATURE=0     # 警告

# 方式二：配置文件
# %ProgramData%\FolderLock\service-settings.json
{ "RequireServiceSignature": true }
```

**风险**：警告模式下，任何人替换 `FolderLock.Service.exe` 都能让服务照常运行，
签名校验只剩审计价值。因此：

- 本地开发、未签名打包验证安装/卸载流程时用警告模式；
- 对外分发的正式包**必须**签名，并显式设置 `FOLDERLOCK_REQUIRE_SIGNATURE=1`（或在安装器中
  写入上述配置文件），否则新版本相对旧版是安全回退；
- 应用主界面状态栏会持续显示“警告模式（未强制）”，安全说明对话框里也会给出切换命令。

### 私钥保管

- PFX 不入库、不复制进构建产物；CI 用 `CODE_SIGN_PFX_BASE64` / `CODE_SIGN_PFX_PASSWORD` 密钥。
- 私钥放在 HSM/令牌或专用签名机，导出的 PFX 用完立即删除。
- 私钥泄露要立即吊销并重签；旧证书保留，用于验证历史版本。

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
