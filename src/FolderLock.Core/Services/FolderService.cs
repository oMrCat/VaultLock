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

    public bool CompressVaults { get; set; } = true;

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
        var record = Require(id);

        try
        {
            VerifyPassword(record, password.Span);

            if (record.IsLocked)
            {
                throw new FolderLockException("该文件夹已处于锁定状态。");
            }

            if (record.EncryptionMode == EncryptionMode.Aes256Gcm)
            {
                LockEncrypted(record, password.Span, progress, cancellationToken);
            }
            else
            {
                LockWithAcl(record);
            }

            UpdateWatchlist();
            Audit(AuditAction.Lock, record, true, record.EncryptionMode.ToString());
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
                if (!_locker.IsLocked(record.Path))
                {
                    _locker.Lock(record.Path);
                    restored = true;
                    Audit(AuditAction.AutoRelock, record, true);
                }
            }
            catch
            {
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
        try
        {
            var paths = _store.GetAll()
                .Where(record => record.IsLocked && record.EncryptionMode != EncryptionMode.Aes256Gcm)
                .Select(record => record.Path);

            _watchlist.Save(paths);
        }
        catch
        {
        }
    }

    public void SyncLockStates()
    {
        foreach (var record in _store.GetAll())
        {
            bool actual;
            if (record.EncryptionMode == EncryptionMode.Aes256Gcm)
            {
                actual = record.VaultPath is not null && File.Exists(record.VaultPath);
            }
            else
            {
                try
                {
                    actual = _locker.IsLocked(record.Path);
                }
                catch
                {
                    continue;
                }
            }

            if (actual != record.IsLocked)
            {
                record.IsLocked = actual;
                _store.Update(record);
            }
        }

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
            backup = _locker.Lock(record.Path);
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            throw new FolderLockException($"锁定失败：{ex.Message}", ex);
        }

        record.DaclSddl = backup.DaclSddl;
        record.AccessRulesProtected = backup.AccessRulesProtected;
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
            _locker.Unlock(record.Path, new SecurityBackup(record.DaclSddl, record.AccessRulesProtected));
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            throw new FolderLockException($"解锁失败：{ex.Message}", ex);
        }

        record.IsLocked = false;
        _store.Update(record);
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
                compress: CompressVaults);

            cancellationToken.ThrowIfCancellationRequested();
            _vault.Verify(vaultPath, password);
        }
        catch (OperationCanceledException)
        {
            TryDeleteVault(vaultPath);
            throw;
        }
        catch (Exception ex) when (ex is not FolderLockException)
        {
            TryDeleteVault(vaultPath);
            throw new FolderLockException($"加密失败：{ex.Message}", ex);
        }

        try
        {
            _secureDeleter.DeleteDirectory(record.Path);
        }
        catch (Exception ex)
        {
            throw new FolderLockException(
                $"内容已加密到 {vaultPath}，但原文件夹无法安全擦除（可能被占用）。请关闭占用程序后重试。",
                ex);
        }

        try
        {
            LastTraceClean = _traceCleaner.Clean(record.Path);
        }
        catch
        {
            LastTraceClean = null;
        }

        record.VaultPath = vaultPath;
        record.IsLocked = true;
        record.LastLockedAt = DateTimeOffset.UtcNow;
        _store.Update(record);
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

            if (File.Exists(vaultPath + ".tmp"))
            {
                File.Delete(vaultPath + ".tmp");
            }
        }
        catch
        {
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
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
