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
- **权限锁**：备份文件夹原始安全描述符（SDDL），写入拒绝 Everyone 的 DACL 并隐藏文件夹，解锁时精确还原；极快、不动数据。
- **AES-256-GCM 加密容器（可选）**：将整个文件夹加密为单个 `.flvault` 容器，采用信封加密（随机 DEK，分别由密码与恢复码包裹）。可抵御管理员与离线拷贝；支持加密前 GZip 压缩。
- **危险路径护栏**：拒绝锁定驱动器根、`Windows`、`System32`、`Program Files*`、`ProgramData`、用户配置根/桌面/文档等。
- 加密/解密前**磁盘空间预检**。

### 安全
- 密码以 `PBKDF2-HMAC-SHA256`（21 万次迭代、随机盐、恒定时间比对）存储，绝不存明文。
- **恢复码**（Crockford Base32）：忘记密码时解锁加密容器；本机用 Windows DPAPI 保护，可导出。
- **内存卫生**：密码/恢复码保存在可清零的 `Secret` 中，剪贴板用完即清。
- **失败限速**：连续错误递增锁定（5 次→30 秒、7 次→5 分钟、10 次→30 分钟）。
- **审计日志**：记录添加/加锁/解锁/改密/密码错误/自动复锁，可导出 CSV。
- **数据库加密**：SQLite 使用 SQLCipher，随机密钥由 DPAPI 保护；旧明文库自动迁移。
- **痕迹清理**：加密后用随机数据覆写源文件再删除，并清理最近使用、跳转列表、常见 MRU 注册表项与缩略图缓存。
- 启动时**自身完整性校验**。

### 自动化
- **自动锁定**：锁屏/注销（Windows 会话通知）、空闲超时、临时解锁到期。
- **全局紧急热键** `Ctrl+Alt+L`：锁定全部、清剪贴板、最小化。
- **托盘常驻**通知；可选开机自启。
- **守护服务**（`FolderLockGuard`）：Windows 服务持续检测并在被篡改时自动复锁。

### 数据安危
- **容器校验与救援**：检查容器、验证可解密，损坏时尽量导出可恢复内容。
- **导出/导入恢复套件**：口令保护的 `.flkit` 备份（文件夹列表、密码哈希、恢复码），可跨机迁移。
- **便携模式**：程序目录放 `portable.flag`，所有数据（数据库/密钥/设置/清单）存于程序旁。

### 体验
- Fluent（Windows 11）界面，浅色/深色/跟随系统主题；侧边筛选、实时搜索、可排序列表、详情面板、空状态。
- 密码强度提示与随机密码生成。
- **中英文界面**。
- 资源管理器右键菜单集成与单实例命令转发。

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
.\installer\publish.ps1 -CertThumbprint <指纹>   # 可选代码签名
```

产物目录：`src\FolderLock.App\bin\Release\<tfm>\publish\win-x64\`（含 `FolderLock.App.exe` 与 `FolderLock.Service.exe`）。

### 安装包

`installer\FolderLock.iss` 为 [Inno Setup](https://jrsoftware.org/isinfo.php) 脚本：先 publish，再编译脚本。

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

超过 130 个单元测试，覆盖口令哈希、ACL 加锁（真实临时目录）、容器往返/损坏、安全擦除、痕迹清理、限速、审计、SQLCipher 加密与迁移、更新版本比较与覆盖图标判定等。

---

## 安全边界（实话实说）

- **权限锁**可阻止本机其他标准用户与随手访问；**不防**管理员、SYSTEM 或安全模式。
- **AES 容器**可防离线访问与管理员，但不防"解锁状态下以你身份运行的恶意软件"，也不防冷启动攻击。
- 安全删除是尽力而为：SSD 的 TRIM/磨损均衡、页面文件、系统搜索索引可能残留副本；强保证请配合全盘加密。
- 加密文件夹的密码一旦丢失，只能靠恢复码还原——请妥善保存。

---

## 许可

[MIT](LICENSE) © 2026 oMrCat
