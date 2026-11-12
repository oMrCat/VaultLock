using FolderLock.Core.Cleanup;
using FolderLock.Core.Data;
using FolderLock.Core.Security;

namespace FolderLock.Core.Services;

public sealed class FolderLockException : Exception
{
    public FolderLockException(string message)
        : base(message)
    {
    }

    public FolderLockException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

public sealed class FolderService
{
    private readonly FolderStore _store;
    private readonly IFolderLocker _locker;
    private readonly VaultEncryptor _vault;
    private readonly SecureDeleter _secureDeleter;
    private readonly TraceCleaner _traceCleaner;
    private readonly WatchlistStore _watchlist;
    private readonly VaultSlotManager _slotManager;
    private readonly VaultRecovery _recovery;
    private readonly LocalUnlockKeyStore _localUnlockKeys;

    public FolderService(
        FolderStore store,
        IFolderLocker locker,
        VaultEncryptor? vault = null,
        SecureDeleter? secureDeleter = null,
        TraceCleaner? traceCleaner = null,
        WatchlistStore? watchlist = null,
        VaultSlotManager? slotManager = null,
        VaultRecovery? recovery = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _locker = locker ?? throw new ArgumentNullException(nameof(locker));
        _vault = vault ?? new VaultEncryptor();
        _slotManager = slotManager ?? new VaultSlotManager(_vault);
        _recovery = recovery ?? new VaultRecovery(_vault);
        _secureDeleter = secureDeleter ?? new SecureDeleter();
        _traceCleaner = traceCleaner ?? new TraceCleaner();
        _watchlist = watchlist ?? new WatchlistStore();
        _store.Initialize();
        _localUnlockKeys = new LocalUnlockKeyStore(_store);
    }

    public TraceCleanResult? LastTraceClean { get; private set; }

    /// <summary>最后一次写入 watchlist 的错误；为空表示写入成功或未尝试。</summary>
    public string? LastWatchlistError { get; private set; }

    /// <summary>最后一次同步状态时无法判定的目录（权限/IO 异常）。</summary>
    public IReadOnlyList<string> LastUnknownPaths { get; private set; } = Array.Empty<string>();

    /// <summary>最后一次加密时因符号链接/目录联接而未进入容器的条目（相对路径）。</summary>
    public IReadOnlyList<string> LastSkippedVaultEntries { get; private set; } = Array.Empty<string>();

    public bool CompressVaults { get; set; } = true;

    /// <summary>是否清理系统共享的缩略图/图标缓存（默认关闭，避免影响所有文件夹）。</summary>
    public bool CleanExplorerCaches { get; set; }

    public IReadOnlyList<FolderRecord> GetAll() => _store.GetAll();

    public FolderRecord? GetByPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return _store.GetByPath(Normalize(path));
    }

    public FolderRecord Add(string path, string password) => Add(path, password, encrypt: false, out _);

    public FolderRecord Add(string path, string password, bool encrypt, out string? recoveryCode)
    {
        using var secret = new Secret(password);
        return Add(path, secret, encrypt, out recoveryCode);
    }

    public FolderRecord Add(string path, Secret password, bool encrypt, out string? recoveryCode)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.IsEmpty)
        {
            throw new FolderLockException("密码不能为空。");
        }

        var normalized = Normalize(path);
        if (!Directory.Exists(normalized))
        {
            throw new FolderLockException($"文件夹不存在：{normalized}");
        }

        PathGuard.EnsureLockable(normalized);

        if (_store.GetByPath(normalized) is not null)
        {
            throw new FolderLockException("该文件夹已在列表中。");
        }

        recoveryCode = null;
        var record = new FolderRecord
        {
            Path = normalized,
            DisplayName = new DirectoryInfo(normalized).Name,
            PasswordHash = PasswordHasher.Hash(password.Span).Encode(),
            IsLocked = _locker.IsLocked(normalized),
        };

        if (encrypt)
        {
            recoveryCode = RecoveryCode.Generate();
            record.EncryptionMode = EncryptionMode.Aes256Gcm;
            record.RecoveryHash = PasswordHasher.Hash(RecoveryCode.Normalize(recoveryCode)).Encode();
            record.ProtectedRecoveryCode = SecretProtector.Protect(recoveryCode);
        }

        var inserted = _store.Insert(record);
        Audit(AuditAction.Add, inserted, true, inserted.EncryptionMode.ToString());
        return inserted;
    }

    public void Lock(
        long id,
        string password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var secret = new Secret(password);
        Lock(id, secret, progress, cancellationToken);
    }

    public void Lock(
        long id,
        Secret password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);

        LastTraceClean = null;
        LastSkippedVaultEntries = Array.Empty<string>();
        var record = Require(id);

        try
        {
            VerifyPassword(record, password.Span);

            if (record.IsLocked)
            {
                throw new FolderLockException("该文件夹已处于锁定状态。");
            }

            // 恢复包（.flkit）可能带入任意路径，锁定/加密前必须重新校验，避免对系统目录等执行 ACL 锁定或整目录加密。
            PathGuard.EnsureLockable(record.Path);

            if (record.EncryptionMode == EncryptionMode.Aes256Gcm)
            {
                LockEncrypted(record, password.Span, progress, cancellationToken);
            }
            else
            {
                LockWithAcl(record);
            }

            UpdateWatchlist();
            var detail = LastSkippedVaultEntries.Count == 0
                ? record.EncryptionMode.ToString()
                : $"{record.EncryptionMode}；{LastSkippedVaultEntries.Count} 项链接/联接点未加密";
            Audit(AuditAction.Lock, record, true, detail);
        }
        catch (Exception ex)
        {
            Audit(AuditAction.Lock, record, false, ex.Message);
            throw;
        }
    }

    public Task LockAsync(
        long id,
        string password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(
            () =>
            {
                using var secret = new Secret(password);
                Lock(id, secret, progress, cancellationToken);
            },
            cancellationToken);
    }

    public Task LockAsync(
        long id,
        Secret password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Lock(id, password, progress, cancellationToken), cancellationToken);
    }

    public void Unlock(
        long id,
        string password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var secret = new Secret(password);
        Unlock(id, secret, progress, cancellationToken);
    }

    public void Unlock(
        long id,
        Secret password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);

        var record = Require(id);

        try
        {
            if (!record.IsLocked)
            {
                throw new FolderLockException("该文件夹当前未锁定。");
            }

            if (record.EncryptionMode == EncryptionMode.Aes256Gcm)
            {
                UnlockEncrypted(record, password.Span, progress, cancellationToken);
            }
            else
            {
                VerifyPassword(record, password.Span);
                UnlockWithAcl(record);
            }

            UpdateWatchlist();
            Audit(AuditAction.Unlock, record, true, record.EncryptionMode.ToString());
        }
        catch (Exception ex)
        {
            Audit(AuditAction.Unlock, record, false, ex.Message);
            throw;
        }
    }

    public Task UnlockAsync(
        long id,
        string password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(
            () =>
            {
                using var secret = new Secret(password);
                Unlock(id, secret, progress, cancellationToken);
            },
            cancellationToken);
    }

    /// <summary>使用 DPAPI 保护的本机 KEK 解锁加密容器（kdf=2 槽）。</summary>
    public void UnlockViaDpapi(
        long id,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var record = Require(id);
        try
        {
            if (!record.IsLocked)
            {
                throw new FolderLockException("该文件夹当前未锁定。");
            }

            if (record.EncryptionMode != EncryptionMode.Aes256Gcm)
            {
                throw new FolderLockException("只有加密容器模式支持本机自动解锁。");
            }

            var machineKey = _localUnlockKeys.TryGet(record.Id)
                ?? throw new FolderLockException("未开启本机自动解锁，或当前用户的 DPAPI 密钥不可用。");

            UnlockEncrypted(record, ReadOnlySpan<char>.Empty, progress, cancellationToken, machineKey);
            UpdateWatchlist();
            Audit(AuditAction.UnlockViaDpapi, record, true);
        }
        catch (Exception ex)
        {
            Audit(AuditAction.UnlockViaDpapi, record, false, ex.Message);
            throw;
        }
    }

    public Task UnlockAsync(
        long id,
        Secret password,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Unlock(id, password, progress, cancellationToken), cancellationToken);
    }

    public void ChangePassword(long id, string currentPassword, string newPassword)
    {
        using var current = new Secret(currentPassword);
        using var next = new Secret(newPassword);
        ChangePassword(id, current, next);
    }

    public void ChangePassword(long id, Secret currentPassword, Secret newPassword)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(newPassword);
        if (newPassword.IsEmpty)
        {
            throw new FolderLockException("新密码不能为空。");
        }

        var record = Require(id);
        VerifyPassword(record, currentPassword.Span);

        if (record.EncryptionMode == EncryptionMode.Aes256Gcm && record.IsLocked)
        {
            throw new FolderLockException("加密文件夹在锁定期间不能修改密码，请先解锁。");
        }

        record.PasswordHash = PasswordHasher.Hash(newPassword.Span).Encode();
        _store.Update(record);
        Audit(AuditAction.ChangePassword, record, true);
    }

    // ===== 密钥槽、恢复向导与密码提示（P1） =====

    /// <summary>列出锁定容器的密钥槽（只读头部，不需要 DEK）。</summary>
    public IReadOnlyList<VaultSlotInfo> ListKeySlots(long id)
    {
        var record = Require(id);
        ValidateLockedVault(record);
        return _slotManager.ListSlots(record.VaultPath!);
    }

    /// <summary>生成“忘记密码”向导的可选通道清单。</summary>
    public VaultRecoveryPlan PlanRecovery(long id, string? recoveryKitPath = null)
    {
        var record = Require(id);
        ValidateLockedVault(record);
        return _recovery.Plan(
            record.VaultPath!,
            _store.GetVaultKeySlots(id),
            hasRecoveryKit: !string.IsNullOrWhiteSpace(recoveryKitPath) && File.Exists(recoveryKitPath),
            machineKeyAvailable: _localUnlockKeys.TryGet(id) is not null);
    }

    /// <summary>逐个尝试恢复通道，失败计入与密码相同的失败限流。</summary>
    public VaultRecoveryResult TryRecoveryChannel(
        long id,
        VaultRecoveryChannelType channel,
        Secret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        var record = Require(id);
        ValidateLockedVault(record);
        EnsureNotLockedOut(record);

        var machineKey = channel == VaultRecoveryChannelType.DpapiUser
            ? _localUnlockKeys.TryGet(id)
            : null;

        var result = _recovery.TryChannel(record.VaultPath!, channel, secret, machineKey);
        if (result.Outcome == VaultRecoveryOutcome.WrongKey)
        {
            RegisterFailure(record, $"恢复通道 {channel} 密钥错误");
        }
        else if (result.Outcome == VaultRecoveryOutcome.Success)
        {
            ClearFailures(record);
        }

        return result;
    }

    /// <summary>恢复向导成功后的“设置新密码”：只替换头部密码槽，不重新加密数据。</summary>
    public void RecoverWithNewPassword(long id, Secret workingSecret, Secret newPassword)
    {
        ArgumentNullException.ThrowIfNull(workingSecret);
        ArgumentNullException.ThrowIfNull(newPassword);
        if (newPassword.IsEmpty)
        {
            throw new FolderLockException("新密码不能为空。");
        }

        var record = Require(id);
        ValidateLockedVault(record);
        EnsureV3(record, workingSecret);

        var path = record.VaultPath!;
        var slots = _slotManager.ListSlots(path);
        var passwordSlot = slots.FirstOrDefault(slot =>
            slot.Kind == VaultSlotKind.Password && slot.IsSupported);

        var spec = new VaultSlotSpec(VaultSlotKind.Password, "主密码", newPassword);
        if (passwordSlot is null)
        {
            _slotManager.AddSlot(path, workingSecret, spec);
        }
        else
        {
            _slotManager.ReplaceSlot(path, workingSecret, passwordSlot.Id, spec);
        }

        record.PasswordHash = PasswordHasher.Hash(newPassword.Span).Encode();
        ClearFailures(record);
        _store.Update(record);
        SyncSlotMetadata(record);
        Audit(AuditAction.RotateSecret, record, true, "恢复后设置新密码");
    }

    /// <summary>添加应急密码槽。</summary>
    public VaultKeySlot AddEmergencyPassword(long id, Secret currentPassword, Secret emergencyPassword)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(emergencyPassword);
        if (emergencyPassword.IsEmpty)
        {
            throw new FolderLockException("应急密码不能为空。");
        }

        var record = Require(id);
        ValidateLockedVault(record);
        EnsureV3(record, currentPassword);

        var slot = _slotManager.AddSlot(
            record.VaultPath!,
            currentPassword,
            new VaultSlotSpec(VaultSlotKind.EmergencyPassword, "应急密码", emergencyPassword));

        AppendSlotRecord(record, slot, SecretProtector.Protect(new string(emergencyPassword.Span)));
        Audit(AuditAction.AddKeySlot, record, true, $"应急密码槽 {slot.Id}");
        return slot;
    }

    /// <summary>删除任意密钥槽（不会允许删除最后一个主密码槽）。</summary>
    public void RemoveKeySlot(long id, Secret currentPassword, Guid slotId)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);

        var record = Require(id);
        ValidateLockedVault(record);
        EnsureV3(record, currentPassword);

        _slotManager.RemoveSlot(record.VaultPath!, currentPassword, slotId);
        SyncSlotMetadata(record);
        Audit(AuditAction.RemoveKeySlot, record, true, $"槽 {slotId}");
    }

    /// <summary>开启本机自动解锁：生成 DPAPI 保护的机器 KEK 并写入 kdf=2 槽。</summary>
    public void EnableLocalUnlock(long id, Secret currentPassword)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);

        var record = Require(id);
        ValidateLockedVault(record);
        EnsureV3(record, currentPassword);

        var slots = _slotManager.ListSlots(record.VaultPath!);
        if (slots.Any(slot => slot.Kind == VaultSlotKind.DpapiUser))
        {
            return;
        }

        var machineKey = _localUnlockKeys.GetOrCreate(id);
        var slot = _slotManager.AddSlot(
            record.VaultPath!,
            currentPassword,
            new VaultSlotSpec(VaultSlotKind.DpapiUser, "本机自动解锁", MachineKey: machineKey));

        AppendSlotRecord(record, slot, null, "本机自动解锁");
        Audit(AuditAction.AddKeySlot, record, true, $"DPAPI 槽 {slot.Id}");
    }

    /// <summary>关闭本机自动解锁：删除 DPAPI 槽与数据库中的机器 KEK。</summary>
    public void DisableLocalUnlock(long id, Secret currentPassword)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);

        var record = Require(id);
        ValidateLockedVault(record);

        var version = _vault.ReadHeaderInfo(record.VaultPath!).Version;
        if (version == VaultHeaderV3.FormatVersion)
        {
            var slots = _slotManager.ListSlots(record.VaultPath!);
            foreach (var slot in slots.Where(slot => slot.Kind == VaultSlotKind.DpapiUser))
            {
                _slotManager.RemoveSlot(record.VaultPath!, currentPassword, slot.Id);
            }

            SyncSlotMetadata(record);
        }

        _localUnlockKeys.Remove(id);
        Audit(AuditAction.RemoveKeySlot, record, true, "删除 DPAPI 槽");
    }

    public bool IsLocalUnlockEnabled(long id) => _store.GetLocalUnlockKey(id) is not null;

    /// <summary>读取密码提示（DPAPI 保护，仅本机本用户可见）。</summary>
    public string? GetPasswordHint(long id)
    {
        var record = Require(id);
        return record.PasswordHintProtected is null
            ? null
            : SecretProtector.Unprotect(record.PasswordHintProtected);
    }

    /// <summary>设置或清除密码提示。需要验证当前密码。</summary>
    public void SetPasswordHint(long id, Secret currentPassword, string? hint)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);

        var record = Require(id);
        VerifyPassword(record, currentPassword.Span);

        record.PasswordHintProtected = string.IsNullOrWhiteSpace(hint)
            ? null
            : SecretProtector.Protect(hint.Trim());
        _store.Update(record);
        Audit(AuditAction.ChangePassword, record, true, "更新密码提示");
    }

    /// <summary>验证密码后再次查看恢复码，并记录查看时间。</summary>
    /// <param name="currentPassword">主密码；7 天查看窗口内可为 null。</param>
    public string? RevealRecoveryCode(long id, Secret? currentPassword = null)
    {
        var record = Require(id);

        if (currentPassword is null)
        {
            if (!CanRevealRecoveryCodeWithoutPassword(record))
            {
                throw new FolderLockException("恢复码查看窗口已过期，请输入主密码。");
            }
        }
        else
        {
            VerifyPassword(record, currentPassword.Span);
        }

        var code = record.ProtectedRecoveryCode is null
            ? null
            : SecretProtector.Unprotect(record.ProtectedRecoveryCode);
        if (code is not null)
        {
            var slot = _store.GetVaultKeySlots(id)
                .FirstOrDefault(slotRecord => slotRecord.Kind == VaultSlotKind.RecoveryCode);
            if (slot is not null)
            {
                _store.MarkVaultKeySlotRevealed(slot.SlotId, DateTimeOffset.UtcNow);
            }

            Audit(AuditAction.RevealRecoveryCode, record, true, slot is null ? null : $"槽 {slot.SlotId}");
        }

        return code;
    }

    /// <summary>创建后 7 天内可凭已解锁状态再次查看恢复码。</summary>
    public bool CanRevealRecoveryCodeWithoutPassword(long id) => CanRevealRecoveryCodeWithoutPassword(Require(id));

    private bool CanRevealRecoveryCodeWithoutPassword(FolderRecord record)
    {
        if (record.ProtectedRecoveryCode is null)
        {
            return false;
        }

        var slot = _store.GetVaultKeySlots(record.Id)
            .FirstOrDefault(slotRecord => slotRecord.Kind == VaultSlotKind.RecoveryCode);

        // 没有槽记录（旧的 v2 容器）时按“最近创建”处理，仍要求主密码更安全。
        var windowStart = slot?.LastRevealedAt ?? slot?.CreatedAt;
        return windowStart is not null &&
               DateTimeOffset.UtcNow - windowStart.Value <= TimeSpan.FromDays(7);
    }

    public void MarkRecoveryCodeBackedUp(long id)
    {
        var record = Require(id);
        record.RecoveryBackedUpAt = DateTimeOffset.UtcNow;
        _store.Update(record);
    }

    /// <summary>30 天未确认备份恢复码时返回 true。</summary>
    public bool NeedsRecoveryBackupReminder(long id)
    {
        var record = Require(id);
        if (record.ProtectedRecoveryCode is null)
        {
            return false;
        }

        return record.RecoveryBackedUpAt is null ||
               DateTimeOffset.UtcNow - record.RecoveryBackedUpAt.Value > TimeSpan.FromDays(30);
    }

    private void ValidateLockedVault(FolderRecord record)
    {
        if (record.EncryptionMode != EncryptionMode.Aes256Gcm)
        {
            throw new FolderLockException("只有加密容器模式支持密钥槽管理。");
        }

        if (!record.IsLocked)
        {
            throw new FolderLockException("请先锁定文件夹后再管理密钥槽。");
        }

        if (record.VaultPath is null || !File.Exists(record.VaultPath))
        {
            throw new FolderLockException("找不到加密容器文件。");
        }
    }

    private void EnsureV3(FolderRecord record, Secret workingSecret)
    {
        var path = record.VaultPath!;
        var info = _vault.ReadHeaderInfo(path);
        if (info.Version == VaultHeaderV3.FormatVersion)
        {
            return;
        }

        if (info.Version != 2)
        {
            throw new FolderLockException("仅支持将 v2 容器升级为 v3。");
        }

        _slotManager.UpgradeToV3(path, workingSecret, keepBackup: true);
        Audit(AuditAction.UpgradeVault, record, true, $"v{info.Version} → v3");
    }

    private void SaveCreatedSlotMetadata(FolderRecord record, string vaultPath, string? recoveryCode)
    {
        var priorEmergency = _store.GetVaultKeySlots(record.Id)
            .Where(slot => slot.Kind == VaultSlotKind.EmergencyPassword)
            .ToList();
        var emergencyIndex = 0;
        var now = DateTimeOffset.UtcNow;
        var records = new List<VaultKeySlotRecord>();

        foreach (var info in _slotManager.ListSlots(vaultPath))
        {
            string? protectedSecret = null;
            var label = DefaultSlotLabel(info.Kind);
            if (info.Kind == VaultSlotKind.RecoveryCode && recoveryCode is not null)
            {
                protectedSecret = SecretProtector.Protect(recoveryCode);
            }
            else if (info.Kind == VaultSlotKind.EmergencyPassword &&
                     emergencyIndex < priorEmergency.Count)
            {
                var prior = priorEmergency[emergencyIndex++];
                protectedSecret = prior.ProtectedSecret;
                label = prior.Label ?? label;
            }

            records.Add(new VaultKeySlotRecord
            {
                SlotId = info.Id,
                FolderId = record.Id,
                Kind = info.Kind,
                Label = label,
                ProtectedSecret = protectedSecret,
                CreatedAt = now,
            });
        }

        _store.ReplaceVaultKeySlots(record.Id, records);
    }

    private void SyncSlotMetadata(FolderRecord record)
    {
        var existing = _store.GetVaultKeySlots(record.Id)
            .ToDictionary(slot => slot.SlotId);
        var now = DateTimeOffset.UtcNow;
        var records = new List<VaultKeySlotRecord>();

        foreach (var info in _slotManager.ListSlots(record.VaultPath!))
        {
            var prior = existing.GetValueOrDefault(info.Id);
            records.Add(new VaultKeySlotRecord
            {
                SlotId = info.Id,
                FolderId = record.Id,
                Kind = info.Kind,
                Label = prior?.Label ?? DefaultSlotLabel(info.Kind),
                ProtectedSecret = prior?.ProtectedSecret,
                CreatedAt = prior?.CreatedAt ?? now,
                LastRevealedAt = prior?.LastRevealedAt,
            });
        }

        _store.ReplaceVaultKeySlots(record.Id, records);
    }

    private void AppendSlotRecord(
        FolderRecord record,
        VaultKeySlot slot,
        string? protectedSecret,
        string? label = null)
    {
        var records = _store.GetVaultKeySlots(record.Id).ToList();
        records.Add(new VaultKeySlotRecord
        {
            SlotId = slot.Id,
            FolderId = record.Id,
            Kind = slot.Kind,
            Label = label ?? DefaultSlotLabel(slot.Kind),
            ProtectedSecret = protectedSecret,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        _store.ReplaceVaultKeySlots(record.Id, records);
    }

    private static string DefaultSlotLabel(VaultSlotKind kind) => kind switch
    {
        VaultSlotKind.Password => "主密码",
        VaultSlotKind.RecoveryCode => "恢复码",
        VaultSlotKind.EmergencyPassword => "应急密码",
        VaultSlotKind.DpapiUser => "本机自动解锁",
        VaultSlotKind.Tpm => "TPM",
        VaultSlotKind.WindowsHello => "Windows Hello",
        _ => "密钥槽",
    };

    public void Remove(long id, string password)
    {
        using var secret = new Secret(password);
        Remove(id, secret);
    }

    public void Remove(long id, Secret password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var record = Require(id);
        VerifyPassword(record, password.Span);

        if (record.IsLocked)
        {
            throw new FolderLockException("请先解锁后再移除。");
        }

        Audit(AuditAction.Remove, record, true);
        _store.Delete(id);
        UpdateWatchlist();
    }

    public bool EnforceLocks()
    {
        var restored = false;
        foreach (var record in _store.GetAll())
        {
            if (!record.IsLocked || record.EncryptionMode == EncryptionMode.Aes256Gcm)
            {
                continue;
            }

            try
            {
                switch (_locker.GetLockState(record.Path))
                {
                    case FolderLockState.Locked:
                        break;
                    case FolderLockState.Unknown:
                        Audit(AuditAction.AutoRelock, record, false, "锁定状态未知（权限/IO 异常），已跳过");
                        break;
                    default:
                        _locker.Lock(record.Path);
                        restored = true;
                        Audit(AuditAction.AutoRelock, record, true);
                        break;
                }
            }
            catch (Exception ex)
            {
                Audit(AuditAction.AutoRelock, record, false, ex.Message);
            }
        }

        return restored;
    }

    public IReadOnlyList<long> LockAll(Keyring keyring)
    {
        return LockAll(keyring, out _);
    }

    /// <summary>
    /// 批量锁定所有已解锁且缓存了密码的文件夹。
    /// 单项失败不再静默吞掉：失败明细通过 <paramref name="failures"/> 返回（供 UI 提示）。
    /// </summary>
    public IReadOnlyList<long> LockAll(Keyring keyring, out List<string> failures)
    {
        ArgumentNullException.ThrowIfNull(keyring);

        var locked = new List<long>();
        var failed = new List<string>();
        foreach (var record in _store.GetAll())
        {
            if (record.IsLocked || !keyring.TryGet(record.Id, out var secret))
            {
                continue;
            }

            try
            {
                Lock(record.Id, secret);
                keyring.Remove(record.Id);
                locked.Add(record.Id);
            }
            catch (Exception ex)
            {
                failed.Add($"{record.DisplayName}：{ex.Message}");
            }
        }

        failures = failed;
        return locked;
    }

    public VaultHeaderInfo InspectVault(long id)
    {
        var record = Require(id);
        if (record.VaultPath is null || !File.Exists(record.VaultPath))
        {
            throw new FolderLockException("找不到加密容器文件。");
        }

        return _vault.ReadHeaderInfo(record.VaultPath);
    }

    public bool VerifyVault(long id, Secret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        var record = Require(id);
        if (record.VaultPath is null || !File.Exists(record.VaultPath))
        {
            throw new FolderLockException("找不到加密容器文件。");
        }

        return _vault.TryVerify(record.VaultPath, secret.Span);
    }

    public SalvageResult SalvageVault(long id, Secret secret, string targetDirectory)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDirectory);

        var record = Require(id);
        if (record.VaultPath is null || !File.Exists(record.VaultPath))
        {
            throw new FolderLockException("找不到加密容器文件。");
        }

        return _vault.SalvageToDirectory(record.VaultPath, targetDirectory, secret.Span);
    }

    /// <summary>只读取头部信息，可用于右键菜单对任意 .flvault 文件的校验。</summary>
    public VaultHeaderInfo InspectVaultFile(string vaultPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        EnsureVaultFileExists(vaultPath);
        return _vault.ReadHeaderInfo(vaultPath);
    }

    /// <summary>校验任意 .flvault 文件；失败返回 false，而不是抛出异常。</summary>
    public bool VerifyVaultFile(string vaultPath, Secret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        EnsureVaultFileExists(vaultPath);
        return _vault.TryVerify(vaultPath, secret.Span);
    }

    /// <summary>把任意 .flvault 文件解密到指定文件夹。</summary>
    public void DecryptVaultFile(string vaultPath, string targetDirectory, Secret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDirectory);
        EnsureVaultFileExists(vaultPath);
        _vault.DecryptToDirectory(vaultPath, targetDirectory, secret.Span);
    }

    /// <summary>抢救任意 .flvault 文件，尽量还原可读内容。</summary>
    public SalvageResult SalvageVaultFile(string vaultPath, Secret secret, string targetDirectory)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDirectory);
        EnsureVaultFileExists(vaultPath);
        return _vault.SalvageToDirectory(vaultPath, targetDirectory, secret.Span);
    }

    private static void EnsureVaultFileExists(string vaultPath)
    {
        if (!File.Exists(vaultPath))
        {
            throw new FolderLockException($"找不到加密容器文件：{vaultPath}");
        }
    }

    public int ExportKit(string kitPath, Secret passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        ArgumentException.ThrowIfNullOrWhiteSpace(kitPath);

        var entries = new List<RecoveryKitEntry>();
        foreach (var record in _store.GetAll())
        {
            entries.Add(new RecoveryKitEntry
            {
                Path = record.Path,
                DisplayName = record.DisplayName,
                PasswordHash = record.PasswordHash,
                RecoveryHash = record.RecoveryHash,
                RecoveryCode = record.ProtectedRecoveryCode is null
                    ? null
                    : SecretProtector.Unprotect(record.ProtectedRecoveryCode),
                EncryptionMode = (int)record.EncryptionMode,
                IsLocked = record.IsLocked,
                DaclSddl = record.DaclSddl,
                AccessRulesProtected = record.AccessRulesProtected,
                VaultPath = record.VaultPath,
            });
        }

        RecoveryKit.Export(kitPath, passphrase.Span, entries);
        Audit(AuditAction.ExportKit, null, true, $"导出 {entries.Count} 项");
        return entries.Count;
    }

    public int ImportKit(string kitPath, Secret passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        ArgumentException.ThrowIfNullOrWhiteSpace(kitPath);

        var entries = RecoveryKit.Import(kitPath, passphrase.Span);
        var added = 0;

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Path) || _store.GetByPath(entry.Path) is not null)
            {
                continue;
            }

            var record = new FolderRecord
            {
                Path = entry.Path,
                DisplayName = string.IsNullOrWhiteSpace(entry.DisplayName)
                    ? Path.GetFileName(Path.TrimEndingDirectorySeparator(entry.Path))
                    : entry.DisplayName,
                PasswordHash = entry.PasswordHash,
                RecoveryHash = entry.RecoveryHash,
                ProtectedRecoveryCode = entry.RecoveryCode is null
                    ? null
                    : SecretProtector.Protect(entry.RecoveryCode),
                EncryptionMode = (EncryptionMode)entry.EncryptionMode,
                DaclSddl = entry.DaclSddl,
                AccessRulesProtected = entry.AccessRulesProtected,
                VaultPath = entry.VaultPath,
                IsLocked = false,
            };

            _store.Insert(record);
            added++;
        }

        SyncLockStates();
        Audit(AuditAction.ImportKit, null, true, $"导入 {added} 项");
        return added;
    }

    public string? GetRecoveryCode(long id)
    {
        var record = Require(id);
        return record.ProtectedRecoveryCode is null
            ? null
            : SecretProtector.Unprotect(record.ProtectedRecoveryCode);
    }

    public void UpdateWatchlist()
    {
        LastWatchlistError = null;

        try
        {
            var paths = _store.GetAll()
                .Where(record => record.IsLocked && record.EncryptionMode != EncryptionMode.Aes256Gcm)
                .Select(record => record.Path);

            _watchlist.Save(paths);
        }
        catch (Exception ex)
        {
            // 不打断已完成的锁定/解锁，但绝不能让写入失败变成静默失败：
            // 记录错误并由 UI/调用方展示，同时写审计。
            LastWatchlistError = ex.Message;
            Audit(AuditAction.WatchlistSync, null, false, $"监控列表写入失败：{ex.Message}");
        }
    }

    public void SyncLockStates()
    {
        var unknown = new List<string>();

        foreach (var record in _store.GetAll())
        {
            bool? actual;
            if (record.EncryptionMode == EncryptionMode.Aes256Gcm)
            {
                actual = record.VaultPath is not null && File.Exists(record.VaultPath);
            }
            else
            {
                try
                {
                    actual = _locker.GetLockState(record.Path) switch
                    {
                        FolderLockState.Locked => true,
                        FolderLockState.Unlocked => false,
                        _ => null,
                    };
                }
                catch (Exception ex)
                {
                    actual = null;
                    unknown.Add($"{record.Path}（{ex.Message}）");
                    continue;
                }
            }

            if (actual is null)
            {
                unknown.Add(record.Path);
                continue;
            }

            if (actual != record.IsLocked)
            {
                record.IsLocked = actual.Value;
                _store.Update(record);
            }
        }

        LastUnknownPaths = unknown;
        UpdateWatchlist();
    }

    private void LockWithAcl(FolderRecord record)
    {
        if (!Directory.Exists(record.Path))
        {
            throw new FolderLockException($"文件夹不存在：{record.Path}");
        }

        SecurityBackup backup;
        try
        {
            backup = _locker.CaptureBackup(record.Path);
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            throw new FolderLockException($"锁定失败：{ex.Message}", ex);
        }

        // 先把权限备份落库，再真正修改 ACL：即使改权限后崩溃，
        // 下次启动也能用已保存的 DACL 恢复，不会出现“锁住了但没有备份”。
        record.DaclSddl = backup.DaclSddl;
        record.AccessRulesProtected = backup.AccessRulesProtected;
        record.OwnerSid = backup.OwnerSid;
        record.OriginalAttributes = backup.OriginalAttributes;
        record.IsLocked = false;
        _store.Update(record);

        try
        {
            _locker.ApplyLock(record.Path, backup);
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            throw new FolderLockException($"锁定失败：{ex.Message}", ex);
        }

        record.IsLocked = true;
        record.LastLockedAt = DateTimeOffset.UtcNow;
        _store.Update(record);
    }

    private void UnlockWithAcl(FolderRecord record)
    {
        if (record.DaclSddl is null)
        {
            throw new FolderLockException("缺少权限备份，无法解锁。");
        }

        try
        {
            _locker.Unlock(
                record.Path,
                new SecurityBackup(
                    record.DaclSddl,
                    record.AccessRulesProtected,
                    record.OwnerSid,
                    record.OriginalAttributes));
        }
        catch (FolderLockAccessException ex)
        {
            throw new FolderLockException(BuildUnlockRecoveryMessage(record, ex), ex);
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            throw new FolderLockException($"解锁失败：{ex.Message}", ex);
        }

        record.IsLocked = false;
        _store.Update(record);
    }

    private static string BuildUnlockRecoveryMessage(FolderRecord record, FolderLockAccessException exception)
    {
        var owner = record.OwnerSid ?? "未知";
        return
            $"解锁失败：目录“{record.Path}”的所有权或权限已被接管，当前进程没有 WRITE_DAC，无法自动恢复。\n" +
            $"加锁时记录的目录所有者 SID：{owner}。\n" +
            "可按以下步骤手动恢复：\n" +
            $"1) 以管理员打开命令提示符，执行：takeown /f \"{record.Path}\" /r /d y\n" +
            $"2) 再执行：icacls \"{record.Path}\" /reset /T /C\n" +
            "3) 回到 FolderLock 重新解锁；若仍失败，请用恢复套件/管理员恢复原 DACL。\n" +
            $"（原始错误：{exception.Message}）";
    }

    private void LockEncrypted(
        FolderRecord record,
        ReadOnlySpan<char> password,
        IProgress<VaultProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(record.Path))
        {
            throw new FolderLockException($"文件夹不存在：{record.Path}");
        }

        DiskSpace.EnsureRoomFor(record.Path);

        var parent = Path.GetDirectoryName(record.Path)
                     ?? throw new FolderLockException("无法确定父目录。");
        var vaultPath = Path.Combine(parent, record.DisplayName + VaultEncryptor.Extension);

        if (File.Exists(vaultPath))
        {
            // 正常流程里解锁时会删除容器；这里仍存在即上次删除失败的残留。
            // 先尝试清理一次（避免锁死在"目标容器已存在，拒绝覆盖"的循环里）；
            // 仍失败则给出可操作的指引，而不是笼统的"锁定失败"。
            try
            {
                File.Delete(vaultPath);
            }
            catch (Exception ex)
            {
                throw new FolderLockException(
                    $"存在残留加密容器 {vaultPath} 且无法删除（可能被占用）：{ex.Message}。请手动删除该文件后重试。",
                    ex);
            }
        }
        var recoveryCode = record.ProtectedRecoveryCode is null
            ? null
            : SecretProtector.Unprotect(record.ProtectedRecoveryCode);

        var created = false;
        var report = new VaultEncryptionReport();
        var machineKey = _localUnlockKeys.TryGet(record.Id);
        var extraSecrets = new List<Secret>();
        var extraSlots = new List<VaultSlotSpec>();
        try
        {
            foreach (var slotRecord in _store.GetVaultKeySlots(record.Id))
            {
                if (slotRecord.Kind != VaultSlotKind.EmergencyPassword ||
                    slotRecord.ProtectedSecret is null)
                {
                    continue;
                }

                var plain = SecretProtector.Unprotect(slotRecord.ProtectedSecret)
                    ?? throw new FolderLockException("应急密码记录已损坏，无法重新写入容器。");
                var secret = new Secret(plain);
                extraSecrets.Add(secret);
                extraSlots.Add(new VaultSlotSpec(
                    VaultSlotKind.EmergencyPassword,
                    slotRecord.Label,
                    secret));
            }

            _vault.EncryptDirectory(
                record.Path,
                vaultPath,
                password,
                recoveryCode,
                PasswordHasher.DefaultIterations,
                progress,
                cancellationToken,
                compress: CompressVaults,
                overwrite: false,
                report: report,
                machineKey: machineKey,
                extraSlots: extraSlots);

            created = true;
            cancellationToken.ThrowIfCancellationRequested();
            _vault.Verify(vaultPath, password);

            SaveCreatedSlotMetadata(record, vaultPath, recoveryCode);
        }
        catch (OperationCanceledException)
        {
            if (created)
            {
                TryDeleteVault(vaultPath);
            }

            throw;
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            // 只有本次确实新建了容器才清理，避免把上一次残留的完整容器误删。
            if (created)
            {
                TryDeleteVault(vaultPath);
            }

            throw new FolderLockException($"加密失败：{ex.Message}", ex);
        }
        finally
        {
            foreach (var secret in extraSecrets)
            {
                secret.Dispose();
            }
        }

        // 先落库再擦除：擦除阶段中途失败时，容器仍是唯一完整副本，
        // 若此时记录仍为“未锁定”，用户重试锁定会以残缺目录覆盖容器造成永久数据丢失。
        record.VaultPath = vaultPath;
        record.IsLocked = true;
        record.LastLockedAt = DateTimeOffset.UtcNow;
        _store.Update(record);
        LastSkippedVaultEntries = report.SkippedEntries.ToArray();

        try
        {
            _secureDeleter.DeleteDirectory(record.Path);
        }
        catch (Exception ex)
        {
            throw new FolderLockException(
                $"内容已完整加密到 {vaultPath}，但原文件夹无法安全擦除（可能被占用）。记录已标记为锁定，请勿重复锁定；" +
                "关闭占用程序后可先用“校验/救援”功能还原，或手动删除残留目录后再解锁。",
                ex);
        }

        try
        {
            LastTraceClean = _traceCleaner.Clean(record.Path, CleanExplorerCaches);
        }
        catch
        {
            LastTraceClean = null;
        }
    }

    private void UnlockEncrypted(
        FolderRecord record,
        ReadOnlySpan<char> secret,
        IProgress<VaultProgress>? progress,
        CancellationToken cancellationToken,
        byte[]? machineKey = null)
    {
        if (record.VaultPath is null || !File.Exists(record.VaultPath))
        {
            throw new FolderLockException("找不到加密容器文件。");
        }

        if (Directory.Exists(record.Path))
        {
            throw new FolderLockException("目标文件夹已存在，无法还原。请先移除或重命名后重试。");
        }

        DiskSpace.EnsureRoomForBytes(record.VaultPath, new FileInfo(record.VaultPath).Length);

        try
        {
            _vault.DecryptToDirectory(
                record.VaultPath,
                record.Path,
                secret,
                progress,
                cancellationToken,
                machineKey);
        }
        catch (OperationCanceledException)
        {
            TryDeleteDirectory(record.Path);
            throw;
        }
        catch (VaultException ex)
        {
            TryDeleteDirectory(record.Path);
            throw new FolderLockException("密码或恢复码不正确，或加密容器已损坏。", ex);
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            // 解密中途的任何异常（磁盘满、路径冲突等）都可能留下部分明文，必须清理。
            TryDeleteDirectory(record.Path);
            throw new FolderLockException($"解密失败：{ex.Message}", ex);
        }

        TryDeleteVault(record.VaultPath);
        record.IsLocked = false;
        _store.Update(record);
    }

    private static void TryDeleteVault(string vaultPath)
    {
        try
        {
            if (File.Exists(vaultPath))
            {
                File.Delete(vaultPath);
            }
        }
        catch
        {
        }
    }

    private void TryDeleteDirectory(string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            try
            {
                _secureDeleter.DeleteDirectory(path);
            }
            catch
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
        }
    }

    private FolderRecord Require(long id)
    {
        return _store.GetById(id) ?? throw new FolderLockException("未找到该文件夹记录。");
    }

    public IReadOnlyList<AuditEntry> GetAudit(int limit = 500) => _store.GetAudit(limit);

    public void ClearAudit() => _store.ClearAudit();

    private void VerifyPassword(FolderRecord record, ReadOnlySpan<char> password)
    {
        if (record.PasswordHash is null)
        {
            throw new FolderLockException("该文件夹尚未设置密码。");
        }

        EnsureNotLockedOut(record);

        var stored = PasswordHash.Decode(record.PasswordHash);
        if (!PasswordHasher.Verify(password, stored))
        {
            RegisterFailure(record, "连续失败");
            throw new FolderLockException("密码错误。");
        }

        ClearFailures(record);
    }

    /// <summary>失败限流：5 次 30 秒、7 次 5 分钟、10 次 30 分钟，密码与恢复通道共用。</summary>
    private void EnsureNotLockedOut(FolderRecord record)
    {
        if (record.LockoutUntil is { } until && until > DateTimeOffset.UtcNow)
        {
            var seconds = Math.Ceiling((until - DateTimeOffset.UtcNow).TotalSeconds);
            throw new FolderLockException($"尝试次数过多，请在 {seconds:0} 秒后重试。");
        }
    }

    private void RegisterFailure(FolderRecord record, string detail)
    {
        var now = DateTimeOffset.UtcNow;
        record.FailedAttempts++;
        var lockout = GetLockout(record.FailedAttempts);
        if (lockout > TimeSpan.Zero)
        {
            record.LockoutUntil = now + lockout;
        }

        _store.Update(record);
        Audit(AuditAction.FailedAttempt, record, false, $"{detail} {record.FailedAttempts} 次");

        if (record.LockoutUntil is { } next && next > now)
        {
            var seconds = Math.Ceiling((next - now).TotalSeconds);
            throw new FolderLockException(
                $"已连续失败 {record.FailedAttempts} 次，请在 {seconds:0} 秒后重试。");
        }
    }

    private void ClearFailures(FolderRecord record)
    {
        if (record.FailedAttempts != 0 || record.LockoutUntil is not null)
        {
            record.FailedAttempts = 0;
            record.LockoutUntil = null;
            _store.Update(record);
        }
    }

    private static TimeSpan GetLockout(int attempts) => attempts switch
    {
        >= 10 => TimeSpan.FromMinutes(30),
        >= 7 => TimeSpan.FromMinutes(5),
        >= 5 => TimeSpan.FromSeconds(30),
        _ => TimeSpan.Zero,
    };

    private void Audit(AuditAction action, FolderRecord? record, bool success, string? detail = null)
    {
        try
        {
            _store.AddAudit(new AuditEntry
            {
                FolderId = record?.Id,
                FolderPath = record?.Path,
                Action = action.ToString(),
                Success = success,
                Detail = detail,
            });
        }
        catch
        {
        }
    }

    private static string Normalize(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }
}
