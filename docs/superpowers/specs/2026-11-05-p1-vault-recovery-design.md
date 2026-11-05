# VaultLock P1 设计：多密钥槽容器、恢复向导与右键菜单

- 日期：2026-11-05
- 状态：待用户确认
- 范围：P1（密码遗忘恢复 + 右键菜单）
- 前置阶段：P2 低成本体验项、P3 安全核心（Argon2id/TPM/TOTP/诱饵密码）+ CLI、P4 数据可靠性

## 1. 背景

VaultLock 的 `.flvault` 容器目前是 v2 格式，头部固定 196 字节，恰好只有两个密钥封装槽：

- 密码派生 KEK 封装 DEK
- 恢复码派生 KEK 封装 DEK

这带来三个问题：

1. 无法增加第三条恢复通道（应急密码、本机自动解锁等）。
2. 忘记密码时，应用无法区分“这个通道不存在”和“通道存在但密码输错”，引导体验差。
3. 密码和恢复码同时丢失时，用户没有任何可执行的自救路径。

同时，现有右键菜单只在 `Directory\shell` 下平铺三个动词，对任意文件夹都显示，且没有 `.flvault` 文件入口。

本设计把两件事一起解决：容器头部升级为可扩展的多槽结构，应用侧补上恢复向导和恢复码强化，并把右键菜单改为级联子菜单。

## 2. 目标与非目标

### 目标

- 新增 v3 容器格式，支持 1 到 8 个密钥槽，槽类型可扩展。
- 换密码、加通道、吊销恢复码只重写头部，不重新加密数据。
- 头部采用 A/B 双份，避免重写过程中崩溃导致容器不可用。
- v1/v2 容器保持只读兼容，不在解锁时自动迁移。
- 提供“忘记密码”向导，逐个通道尝试并给出明确结论。
- 恢复码强制确认、可打印、限时可再次查看、定期备份提醒。
- 右键菜单改为 `VaultLock ▸` 级联，覆盖文件夹与 `.flvault` 文件，支持多选。

### 非目标（本期不做）

- TPM、Windows Hello 槽的实际实现（格式预留，P3 实现）。
- Argon2id（格式预留 KDF 枚举，P3 实现）。
- Shamir 分片、企业密钥托管、硬件密钥。
- `IExplorerCommand` COM 扩展（动态菜单），P1 继续用注册表级联。
- 保管库快照、并行加密、数据保真增强（P4）。

## 3. 现状约束

- 本地无 git 仓库，仅有源码副本 `VaultLock-master`；所有改动只在本地进行，不做远程写操作。
- 已在本机安装 .NET 8 SDK 8.0.427 到 `.dotnet`，不修改系统环境变量。
- WPF + .NET 8，Core 层不依赖 UI，现有 202 个 xUnit 测试。
- 数据库为 SQLCipher，已有 `EnsureColumn` 形式的增量迁移。

## 4. 模块划分

| 模块 | 位置 | 职责 |
|---|---|---|
| `VaultKeySlot` / `VaultSlotKind` | `Core/Security/VaultKeySlot.cs` | 槽模型、ID、类型、KDF 参数 |
| `VaultHeaderV3` | `Core/Security/VaultHeaderV3.cs` | 头部块编解码、CRC、A/B 选择、HMAC |
| `VaultSlotManager` | `Core/Security/VaultSlotManager.cs` | 加槽、删槽、轮换、升级 v2→v3 |
| `VaultEncryptor`（改） | `Core/Security/VaultEncryptor.cs` | 创建 v3、按槽解锁、复用现有数据块实现 |
| `LocalUnlockKeyStore` | `Core/Security/LocalUnlockKeyStore.cs` | DPAPI 保护的本机 KEK（供 kdf=2 槽使用） |
| `VaultRecovery` | `Core/Services/VaultRecovery.cs` | 通道枚举、逐通道尝试、结果分类 |
| `FolderStore`（改） | `Core/Data/FolderStore.cs` | 新表 `VaultKeySlots`、提示字段 |
| `RecoveryWizardWindow` | `App/RecoveryWizardWindow.xaml(.cs)` | 恢复向导 UI |
| `ShellMenuSpec` | `App/ShellMenuSpec.cs` | 纯函数生成菜单项定义（可单测） |
| `ShellIntegration`（改） | `App/ShellIntegration.cs` | 按 spec 写入/清理注册表 |

约束：每个文件保持单一职责，`VaultEncryptor` 只做编排和数据处理，格式细节全部下沉到 `VaultHeaderV3`。

## 5. v3 容器格式

### 5.1 整体布局

```
[ 0 .. 4096 )        头部区（A/B 双块，每块 2048 字节）
[ 4096 .. EOF )      数据块，与 v2 完全相同
```

数据块格式不变：`4 长度 + 12 nonce + N 密文 + 16 标签`，AAD 为块序号；结束块记录块数与明文总字节数。因此把 payload 整体平移 4096 字节不影响认证。

### 5.2 头部块

每块固定 2048 字节：

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 6 | 魔数 `FLVLT1`（沿用） |
| 6 | 1 | 版本 `3` |
| 7 | 1 | flags：bit0 压缩 |
| 8 | 4 | 序号 `uint32 LE` |
| 12 | 1 | 槽数（1..8） |
| 13 | 3 | 保留，必须为 0 |
| 16 | 8×104 | 槽数组，未用槽填零 |
| 848 | 4 | 块校验（SHA-256 前 4 字节，覆盖 `[0,848)`） |
| 852 | 32 | HMAC-SHA256(DEK)，覆盖 `[0,852)` |
| 884 | 1164 | 保留，必须为 0 |

### 5.3 槽结构（104 字节）

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 16 | 槽 ID（随机 GUID，稳定不变） |
| 16 | 1 | 类型 |
| 17 | 1 | KDF |
| 18 | 4 | KDF 参数 1（PBKDF2 迭代数 / Argon2 内存 KiB） |
| 22 | 4 | KDF 参数 2（Argon2 迭代数，PBKDF2 填 0） |
| 26 | 1 | KDF 参数 3（Argon2 并行度，PBKDF2 填 0） |
| 27 | 1 | 保留，0 |
| 28 | 16 | 盐（kdf=2 时全零） |
| 44 | 60 | 封装密钥：12 nonce + 32 密文 + 16 标签 |

槽类型：

| 值 | 类型 | 说明 |
|---|---|---|
| 0 | `Password` | 主密码，至少一个 |
| 1 | `RecoveryCode` | 恢复码，可多份 |
| 2 | `EmergencyPassword` | 应急密码 |
| 3 | `DpapiUser` | 本机自动解锁（P1 实现） |
| 4 | `Tpm` | 保留（P3） |
| 5 | `WindowsHello` | 保留（P3） |

KDF：

| 值 | 算法 |
|---|---|
| 0 | PBKDF2-HMAC-SHA256（P1） |
| 1 | Argon2id（保留，P3） |
| 2 | 外部提供的 32 字节机器 KEK（kdf=2 槽使用，盐全零、参数全零） |

未知类型或未知 KDF 的槽在读取时**跳过而不是报错**，以便未来版本向后兼容；若没有任何可用槽则报“容器没有可用解锁通道”。

### 5.4 头部读写规则

1. 读：解析两块，要求魔数与版本正确、块校验有效。选“校验有效且序号最大”的一块。
2. 若两块都无效：`VaultException("容器头部损坏，建议使用抢救功能或备份")`。
3. 用用户输入匹配各槽，解出 DEK 后计算 HMAC；HMAC 不匹配即判定为篡改，拒绝继续。
4. 写：修改非活动块，序号 = 当前序号 + 1，写入并 flush；读回校验通过后，把旧块清零并 flush。
5. DEK 不变，因此槽增删不需要重新加密 payload。
6. 槽数上限 8，超出时报错；槽 ID 不可重复。

### 5.5 本机自动解锁（kdf=2）

DPAPI 加密后的 32 字节随机 KEK 不存在头部，而是存在 SQLCipher 数据库的 `LocalUnlockKeys` 表中，由 DPAPI（CurrentUser）保护。头部槽用该 KEK 正常封装 DEK，盐和 KDF 参数填零，正好占 60 字节封装空间。

代价必须写进 UI 和文档：同机同用户可绕过密码解锁，任何能读取该用户 DPAPI 密钥的进程都能解封。该通道默认关闭，开启时二次确认。

### 5.6 升级与兼容

- v1/v2 继续可读，写入仍默认 v2，直到 v3 测试全绿后切换到 v3 默认。
- v2 → v3 升级是显式操作：复制原文件为 `.bak`，写临时新文件（4096 头 + 原 payload 原始字节），校验后替换。
- 升级不重新加密数据；耗时主要是磁盘 I/O。
- 绝不自动迁移，不在解锁流程里偷改用户文件。

## 6. 密钥槽管理

公开 API（Core 层）：

```csharp
public enum VaultSlotKind { Password = 0, RecoveryCode = 1, EmergencyPassword = 2, DpapiUser = 3, Tpm = 4, WindowsHello = 5 }

public sealed record VaultSlotSpec(VaultSlotKind Kind, string Label, Secret? Secret);

public IReadOnlyList<VaultSlotInfo> ListSlots(string vaultPath);           // 不需要 DEK
public void AddSlot(string vaultPath, Secret existingSecret, VaultSlotSpec spec);
public void RemoveSlot(string vaultPath, Secret existingSecret, Guid slotId);
public void ReplaceSlot(string vaultPath, Secret existingSecret, Guid slotId, VaultSlotSpec spec);
public void UpgradeToV3(string vaultPath, Secret existingSecret, bool keepBackup = true);
```

规则：

- 任何时候必须至少保留一个 `Password` 槽。
- 删除最后一个 `RecoveryCode` 槽时给出警告，但允许（尊重用户选择）。
- `ReplaceSlot` 覆盖“换密码 / 轮换恢复码”两个场景。
- 所有写操作先校验 `existingSecret`，失败则不做任何写入。
- 失败恢复：临时文件 + 原文件保留，绝不就地截断。

## 7. 恢复向导

### 7.1 通道枚举

`VaultRecovery.Plan(vaultPath)` 返回可用通道清单（只读头部，不需要 DEK）：

- 每个恢复码槽（显示标签）
- 应急密码槽
- 本机自动解锁槽（并检测 DPAPI 当前用户是否可用）
- 恢复套件（存在 `.flkit` 时提示导入）
- 不存在的通道显示为灰色，并说明原因

### 7.2 流程

1. 用户点“忘记密码？”
2. 逐通道尝试，每次输入后立即给出三类结果之一：
   - 通道不存在
   - 通道存在，但密钥错误
   - 成功
3. 成功后进入“设置新密码”，调用 `AddSlot(Password)` + `RemoveSlot(旧密码)`。
4. 全部失败后显示明确结论：密码学上不可恢复；提供抢救工具入口与备份建议，不显示“正在尝试破解”之类误导文案。
5. 全程不把用户输入写入日志；只记录通道类型与成功/失败。

### 7.3 恢复码强化

- 创建加密库时默认要求保存恢复码；只有显式勾选“我接受数据不可恢复的风险”才能跳过。
- 展示页提供：打印卡片、二维码、复制到剪贴板（复制后清空）、7 天内可再次查看。
- 7 天窗口内可凭已解锁状态再次查看；窗口过期后必须重新输入主密码，防止无人值守泄露。
- 若 30 天未备份恢复码，主界面显示提醒。
- 可选“恢复演练”：创建一个临时小容器，用当前恢复码解开，验证用户手上的码确实有效。
- 密码提示：DPAPI 保护后存数据库，标注“仅本机本用户可见”，不进入容器头部。

## 8. 数据库变更

新增表：

```sql
CREATE TABLE IF NOT EXISTS VaultKeySlots (
    SlotId TEXT PRIMARY KEY,
    FolderId INTEGER NOT NULL,
    Kind INTEGER NOT NULL,
    Label TEXT NULL,
    ProtectedSecret TEXT NULL,
    CreatedAt TEXT NOT NULL,
    LastRevealedAt TEXT NULL
);

CREATE TABLE IF NOT EXISTS LocalUnlockKeys (
    FolderId INTEGER PRIMARY KEY,
    ProtectedKey TEXT NOT NULL
);
```

新增列（沿用 `EnsureColumn`）：

- `Folders.PasswordHintProtected TEXT NULL`
- `Folders.RecoveryBackedUpAt TEXT NULL`

说明：

- 恢复码本体只存 DPAPI 保护后的副本（`ProtectedSecret`），不存明文。
- 槽标签存在数据库，不进头部，避免泄露“某人的恢复码”这类元数据。
- v2 容器没有槽记录时，按旧字段 `ProtectedRecoveryCode` 兼容读取。

## 9. 右键菜单

### 9.1 结构

`ShellMenuSpec` 根据 exe 路径、语言、安装范围生成如下定义：

```
Software\Classes\Directory\shell\VaultLock
  (default)   = "VaultLock"
  Icon        = <exe>
  SubCommands = ""            ← 级联必需，且父键不能有 command
  shell\01lock      "加锁"          --lock "%1"
  shell\02unlock    "解锁"          --unlock "%1"
  shell\03add       "加入保护列表"  --add "%1"
  shell\04remove    "移出保护列表"  --remove "%1"
  shell\05open      "在 VaultLock 中打开" --open "%1"
```

`.flvault` 文件：

```
Software\Classes\SystemFileAssociations\.flvault\shell\VaultLock
  shell\01verify    "验证容器"      --verify "%1"
  shell\02decrypt   "解密到文件夹"  --decrypt "%1"
  shell\03salvage   "抢救容器"      --salvage "%1"
  shell\04open      "在 VaultLock 中打开" --open "%1"
```

细节：

- 每个动词设置 `MultiSelectModel=Player`，让 Explorer 一次传入多个选中项。
- 不改 `.flvault` 默认打开方式，只追加动词，避免和第三方程序冲突。
- 安装范围可选 HKCU（默认，无需管理员）或 HKLM（需管理员）。
- `Uninstall` 删除整棵 `VaultLock` 子树，不只删叶子键。
- 菜单标签按当前 UI 语言生成；切换语言后重新安装。
- 菜单是静态的，无法显示“已保护/未保护”；真正动态需要 COM `IExplorerCommand`，P1 不做，由应用在收到命令后校验状态并提示。

### 9.2 命令处理

`App.xaml.cs` 的参数解析扩展为：

```
--lock "%1" --unlock "%1" --add "%1" --remove "%1" --open "%1"
--verify "%1" --decrypt "%1" --salvage "%1"
```

多路径参数逐个处理；单实例转发沿用现有 `SingleInstance`。无法识别的路径给出明确错误，不静默失败。

## 10. 错误处理

| 场景 | 行为 |
|---|---|
| 头部两块 CRC 都无效 | 拒绝解锁，提示抢救/备份，不尝试写入 |
| HMAC 不匹配 | 判定篡改，拒绝，不修改文件 |
| 槽数 > 8 / 槽 ID 重复 | 容器非法，拒绝 |
| KDF 参数超限（迭代 > 5,000,000） | 拒绝，防 DoS |
| DPAPI 在别的机器不可用 | 该槽跳过，向导说明原因 |
| 升级时磁盘空间不足 | 先检查剩余空间，失败时保留原文件与 `.bak` |
| 菜单命令路径不存在 | 托盘提示 + 定位到对应列表项 |
| 注册表安装失败 | 回滚已写入的键，报明确错误 |

补充约束：

- 恢复向导的每次失败尝试都计入现有失败限流（5→30s、7→5min、10→30min），不因为通道多样而放宽。
- 新增审计动作：`AddKeySlot`、`RemoveKeySlot`、`RotateSecret`、`RevealRecoveryCode`、`UnlockViaDpapi`、`UpgradeVault`，沿用现有审计表与 CSV 导出。
- 恢复向导不记录用户输入内容，只记录通道类型、槽 ID 与结果。

## 11. 测试计划

### 11.1 新增单测（Core）

- v3 头部字节布局黄金样本（锁定格式，防止无意改动）。
- 密码 / 恢复码 / 应急密码 / DPAPI 四类槽分别解锁。
- 多恢复码：多个槽都能解，删除一个后其余仍可解。
- 删槽、加槽、换密码、轮换恢复码后，旧密钥失效、新密钥可用。
- A/B 双块：序号选择、撕裂写入回退、旧块清零后仍可读。
- 篡改 flags / 槽数组 / CRC / HMAC 均被拒绝。
- 截断头部、截断 payload、槽数越界。
- v1 / v2 读取兼容；v2→v3 升级后内容逐文件一致。
- 头部不包含明文标签或恢复码。
- KDF 参数上限、未知槽类型跳过。
- `VaultRecovery` 通道计划与“不存在 / 密钥错误 / 成功”三态。
- `ShellMenuSpec` 生成的键路径、标签、参数、范围。

### 11.2 手工/集成验证

- 在真实 Windows 上安装/卸载右键菜单，验证级联、图标、多选、`.flvault` 动词。
- 用临时文件夹验证升级、换密码、恢复码解锁全流程。
- 用 DPAPI 槽在重启后自动解锁，并验证换用户后不可用。

### 11.3 回归

- 现有 202 个测试全部通过；`dotnet test` 作为准入门槛。
- 先写格式测试再改实现；v2 写入路径保留到 v3 全绿。

## 12. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 头部格式解析错误 | 容器不可读，数据丢失 | 黄金样本 + 属性测试 + 保留 v2 写入 + 升级前 `.bak` |
| A/B 重写时序错误 | 崩溃后头部损坏 | 写新块→flush→读回校验→清旧块；集成测试模拟中断 |
| DPAPI 槽削弱安全性 | 同机同用户可绕过密码 | 默认关闭、开启时警告、文档写明威胁模型 |
| 恢复码多副本泄露 | 降低安全性 | 存 DPAPI 保护副本，查看需主密码，审计记录 |
| 注册表菜单污染 | 用户反感 | 级联子菜单、可完整卸载、HKCU 默认 |
| 多选命令参数差异 | 批量失效 | 统一 `MultiSelectModel=Player`，多路径逐个处理 |

## 13. 验收标准

- 新建容器为 v3，包含密码与至少一份恢复码槽。
- 密码、恢复码、应急密码、本机自动解锁均可解锁同一容器。
- 换密码只重写头部，payload 字节不变（可用哈希验证）。
- v2 容器可读、可显式升级，升级前后内容一致。
- 头部被篡改或截断时明确拒绝，不覆盖原文件。
- 忘记密码向导按通道给出准确结论，全部失败时明确告知不可恢复。
- 右键菜单安装/卸载干净，级联显示，多选可用。
- 现有与新增测试全部通过。
