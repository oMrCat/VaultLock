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

    public FolderService(
        FolderStore store,
        IFolderLocker locker,
        VaultEncryptor? vault = null,
        SecureDeleter? secureDeleter = null,
        TraceCleaner? traceCleaner = null,
        WatchlistStore? watchlist = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _locker = locker ?? throw new ArgumentNullException(nameof(locker));
        _vault = vault ?? new VaultEncryptor();
        _secureDeleter = secureDeleter ?? new SecureDeleter();
        _traceCleaner = traceCleaner ?? new TraceCleaner();
        _watchlist = watchlist ?? new WatchlistStore();
        _store.Initialize();
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
        ArgumentNullException.ThrowIfNull(keyring);

        var locked = new List<long>();
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
            catch
            {
            }
        }

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
        var recoveryCode = record.ProtectedRecoveryCode is null
            ? null
            : SecretProtector.Unprotect(record.ProtectedRecoveryCode);

        var created = false;
        var report = new VaultEncryptionReport();
        try
        {
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
                report: report);

            created = true;
            cancellationToken.ThrowIfCancellationRequested();
            _vault.Verify(vaultPath, password);
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
        CancellationToken cancellationToken)
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
            _vault.DecryptToDirectory(record.VaultPath, record.Path, secret, progress, cancellationToken);
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

        var now = DateTimeOffset.UtcNow;
        if (record.LockoutUntil is { } until && until > now)
        {
            var seconds = Math.Ceiling((until - now).TotalSeconds);
            throw new FolderLockException($"尝试次数过多，请在 {seconds:0} 秒后重试。");
        }

        var stored = PasswordHash.Decode(record.PasswordHash);
        if (!PasswordHasher.Verify(password, stored))
        {
            record.FailedAttempts++;
            var lockout = GetLockout(record.FailedAttempts);
            if (lockout > TimeSpan.Zero)
            {
                record.LockoutUntil = now + lockout;
            }

            _store.Update(record);
            Audit(AuditAction.FailedAttempt, record, false, $"连续失败 {record.FailedAttempts} 次");

            if (record.LockoutUntil is { } next && next > now)
            {
                var seconds = Math.Ceiling((next - now).TotalSeconds);
                throw new FolderLockException($"密码错误。已连续失败 {record.FailedAttempts} 次，请在 {seconds:0} 秒后重试。");
            }

            throw new FolderLockException("密码错误。");
        }

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
