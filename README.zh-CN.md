# VaultLock

**VaultLock**（内部工程名：`FolderLock`）是一款现代化的 Windows 文件夹加密加锁工具。
它把快速的 NTFS 权限锁与可选的 **AES-256-GCM 真加密容器**结合在一起，并附带
安全擦除、痕迹清理、自动锁定、恢复码与后台守护服务，界面为 Fluent（Windows 11 风格）。

> Windows 工程/命名空间沿用历史名 `FolderLock`，对外产品名为 **VaultLock**。

[English README](README.md) · [文档](docs/wiki/中文文档.md) · [Wiki](https://github.com/oMrCat/VaultLock/wiki)

---

## 截图

![VaultLock 主界面](docs/images/main-window.png)

---

## 功能

### 加锁
- **权限锁**：备份文件夹原始安全描述符（SDDL），写入拒绝 Everyone 的 DACL 并隐藏文件夹；解锁时重新应用备份的 DACL，但**不是**逐字节回滚所有权/继承变更，所有权被他人接管时需手动恢复（`takeown` + `icacls`）。加锁前会预检 `WRITE_DAC`，权限不足会明确拒绝并提示，避免形成“只能锁、不能解”的单向锁；极快、不动数据。
- **AES-256-GCM 加密容器（可选）**：将整个文件夹加密为单个 `.flvault` 容器，采用信封加密（随机 DEK，由 1~8 个密钥槽分别包裹：密码、恢复码、应急密码、本机 DPAPI）。可抵御管理员与离线拷贝；新容器使用 **v3** 格式（A/B 双头部块 + 认证结束块，可检测元数据篡改与截断），**v2** 容器只读并支持就地升级为 v3，**v1** 仅可读；支持加密前 GZip 压缩。
- **危险路径护栏**：拒绝锁定驱动器根、`Windows`、`System32`、`Program Files*`、`ProgramData`、用户配置根/桌面/文档等。
- 加密/解密前**磁盘空间预检**。

### 安全
- 密码以 `PBKDF2-HMAC-SHA256`（21 万次迭代、随机盐、恒定时间比对）存储，绝不存明文。
- **恢复码**（Crockford Base32）：忘记密码时解锁加密容器；本机用 Windows DPAPI 保护，可打印、复制后自动清空剪贴板，创建后 7 天内可再次查看，超过 30 天未确认备份会在状态栏提醒。
- **多通道恢复**：密码之外的恢复码、应急密码、本机自动解锁（DPAPI）可各自独立解锁；“忘记密码”向导逐通道给出“通道不存在 / 密钥错误 / 成功”的明确结论。
- **密码提示**：DPAPI 保护的本机提示，仅写入本地数据库，不进入容器。
- **内存卫生**：密码/恢复码保存在可清零的 `Secret` 中，剪贴板用完即清。
- **失败限速**：连续错误递增锁定（5 次→30 秒、7 次→5 分钟、10 次→30 分钟）。
- **审计日志**：记录添加/加锁/解锁/改密/密码错误/自动复锁，可导出 CSV。
- **数据库加密**：SQLite 使用 SQLCipher，随机密钥由 DPAPI 保护；旧明文库自动迁移。
- **痕迹清理**：加密后用随机数据覆写源文件再删除，并清理最近使用、跳转列表、常见 MRU 注册表项与缩略图缓存。
- **自身完整性校验**：主程序与守护服务校验自身 Authenticode 签名；配置了预期发布者（`FOLDERLOCK_EXPECTED_PUBLISHERS` 或 `expected-publishers.txt`）时还校验签名者身份。
- **更新校验**：更新器只接受 HTTPS，校验更新包 SHA-256 哈希并核验 Authenticode 签名后才应用。

### 自动化
- **自动锁定**：锁屏/注销（Windows 会话通知）、空闲超时、临时解锁到期。若关闭了密码缓存，没有密码就无法自动重锁，此时会明确提示手动锁定，而不是静默失败。
- **全局紧急热键** `Ctrl+Alt+L`：锁定全部、清剪贴板、最小化。
- **托盘常驻**通知；可选开机自启。
- **守护服务**（`FolderLockGuard`）：以 `NT AUTHORITY\LocalService` 运行的 Windows 服务，持续检测并在被篡改时自动复锁。签名校验默认**警告模式**（只记录）；设 `FOLDERLOCK_REQUIRE_SIGNATURE=1`（或 `%ProgramData%\FolderLock\service-settings.json` 中 `RequireServiceSignature: true`）后才会拒绝未签名/签名不符的可执行文件。

### 数据安危
- **容器校验与救援**：检查容器、验证可解密，损坏时尽量导出可恢复内容。
- **导出/导入恢复套件**：口令保护的 `.flkit` 备份（文件夹列表、密码哈希、恢复码），可跨机迁移。
- **便携模式**：程序目录放 `portable.flag`，所有数据（数据库/密钥/设置/清单）存于程序旁。

### 体验
- Fluent（Windows 11）界面，浅色/深色/跟随系统主题；侧边筛选、实时搜索、可排序列表、详情面板、空状态。
- 密码强度提示与随机密码生成。
- **中英文界面**。
- 资源管理器右键菜单级联（文件夹：加锁/解锁/加入列表/移出列表/打开；`.flvault`：验证/解密/抢救/打开），默认写入 HKCU，支持多选；单实例命令转发。

---

## 运行要求

- Windows 10 1809+ 或 Windows 11（x64）。
- 框架依赖发布需安装 [.NET 8 桌面运行时](https://dotnet.microsoft.com/download/dotnet/8.0)。
- 编译需 .NET 8 SDK。

## 快速开始

```powershell
dotnet run --project src\FolderLock.App   # 运行
dotnet test                               # 测试
```

### 发布

```powershell
.\installer\publish.ps1            # 完整版（含 Windows Hello），约 35MB 单文件
.\installer\publish.ps1 -NoHello   # 精简版（不含 Hello），约 9MB
.\installer\publish.ps1 -Sign -Thumbprint <指纹>   # 可选代码签名（需 signtool 在 PATH）
```

产物目录：`artifacts\publish\win-x64\`（含 `FolderLock.App.exe` 与 `FolderLock.Service.exe`）。Inno Setup 脚本与 `install-service.ps1` 都读取这个固定路径。

### 安装包

`installer\FolderLock.iss` 为 [Inno Setup](https://jrsoftware.org/isinfo.php) 脚本：先 publish，再编译脚本。

安装包按机器安装（`{autopf}`，需要管理员权限）：程序目录对普通用户只读，数据位于 `%ProgramData%\FolderLock`。

> GitHub Release 上当前的安装包**未签名**：Windows 会提示“未知发布者”，守护服务运行在**警告模式**（签名问题只记日志、不阻止启动）。这用于本地验证；正式分发请用受信任证书签名，并设置 `FOLDERLOCK_REQUIRE_SIGNATURE=1`。

### 守护服务（可选，需管理员）

```powershell
.\installer\install-service.ps1
.\installer\uninstall-service.ps1
```

或在应用内 *工具 → 安装守护服务*。

---

## 使用

1. 启动后点击**添加文件夹**（或把文件夹拖入）。
2. 设置密码；如需强加密勾选 **AES-256**，并保存弹出的恢复码。
3. 选中后点击**加锁/解锁**。加密操作会显示进度浮层，可取消。
4. *工具*（⋯）中可切换主题/语言、设置自动锁定与紧急热键、查看日志、校验/救援容器、导出/导入恢复套件、安装守护服务。

---

## 工程结构

| 工程 | 说明 |
|---|---|
| `src/FolderLock.Core` | 加密、容器、ACL、清理、存储、服务 |
| `src/FolderLock.App` | WPF（Fluent）桌面应用 |
| `src/FolderLock.Service` | 后台守护 Windows 服务 |
| `tests/FolderLock.Core.Tests` | xUnit 测试 |
| `installer/` | 发布、服务与 Inno Setup 脚本 |

## 测试

```powershell
dotnet test
```

202 个单元测试，覆盖口令哈希、ACL 加锁（真实临时目录，含 `WRITE_DAC` 预检）、容器往返/损坏（v1 读取兼容与 v2 认证）、安全擦除、痕迹清理、限速、审计、SQLCipher 加密与迁移、更新版本比较、HTTPS/哈希/签名校验与覆盖图标判定等。

---

## 安全边界（实话实说）

- **权限锁**可阻止本机其他标准用户与随手访问；**不防**管理员、SYSTEM 或安全模式。管理员取得所有权并改权限后，解锁只能重新应用备份的 DACL，所有权需用 `takeown` + `icacls` 手动恢复。
- **AES 容器**可防离线访问与管理员，但不防"解锁状态下以你身份运行的恶意软件"，也不防冷启动攻击。只有 v2 容器对元数据做完整性认证；v1 为只读旧格式，不会原地升级。
- **守护服务签名校验**默认警告模式：替换 `FolderLock.Service.exe` 只会被记录，服务照常运行。要真正拦截，需用受信任证书签名并设置 `FOLDERLOCK_REQUIRE_SIGNATURE=1`。
- 安全删除是尽力而为：SSD 的 TRIM/磨损均衡、页面文件、系统搜索索引可能残留副本；强保证请配合全盘加密。
- 加密文件夹的密码一旦丢失，只能靠恢复码还原——请妥善保存。

---

## 许可

[MIT](LICENSE) © 2026 oMrCat
