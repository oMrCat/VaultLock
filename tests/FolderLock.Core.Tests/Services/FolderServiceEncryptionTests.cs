using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public sealed class FolderServiceEncryptionTests : IDisposable
{
    private const string Password = "encrypt-pass";

    private readonly string _root;
    private readonly string _folder;
    private readonly FolderService _service;

    public FolderServiceEncryptionTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Vaulted");
        Directory.CreateDirectory(Path.Combine(_folder, "nested"));
        File.WriteAllText(Path.Combine(_folder, "data.txt"), "secret content");
        File.WriteAllText(Path.Combine(_folder, "nested", "inner.txt"), "inner");

        var dbPath = Path.Combine(_root, "folderlock.db");
        _service = new FolderService(
            new FolderStore(dbPath),
            new FolderLocker(),
            watchlist: new WatchlistStore(Path.Combine(_root, "watchlist.json")));
    }

    [Fact]
    public void Add_WithEncryption_StoresModeAndRecoveryCode()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out var recoveryCode);

        Assert.Equal(EncryptionMode.Aes256Gcm, record.EncryptionMode);
        Assert.NotNull(recoveryCode);
        Assert.NotNull(record.RecoveryHash);
        Assert.NotNull(_service.GetRecoveryCode(record.Id));
    }

    [Fact]
    public void LockEncrypted_ReplacesFolderWithVault()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);

        _service.Lock(record.Id, Password);

        var loaded = _service.GetAll().Single();
        Assert.True(loaded.IsLocked);
        Assert.False(Directory.Exists(_folder));
        Assert.NotNull(loaded.VaultPath);
        Assert.True(File.Exists(loaded.VaultPath));
        Assert.Equal(".flvault", Path.GetExtension(loaded.VaultPath));
    }

    [Fact]
    public void LockEncrypted_ThenUnlockWithPassword_RestoresContent()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);
        _service.Lock(record.Id, Password);

        _service.Unlock(record.Id, Password);

        var loaded = _service.GetAll().Single();
        Assert.False(loaded.IsLocked);
        Assert.True(Directory.Exists(_folder));
        Assert.False(File.Exists(loaded.VaultPath));
        Assert.Equal("secret content", File.ReadAllText(Path.Combine(_folder, "data.txt")));
        Assert.Equal("inner", File.ReadAllText(Path.Combine(_folder, "nested", "inner.txt")));
    }

    [Fact]
    public void LockEncrypted_ThenUnlockWithRecoveryCode_RestoresContent()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out var recoveryCode);

        _service.Lock(record.Id, Password);
        _service.Unlock(record.Id, recoveryCode!);

        Assert.Equal("secret content", File.ReadAllText(Path.Combine(_folder, "data.txt")));
    }

    [Fact]
    public void UnlockEncrypted_WithWrongSecretThrows()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);
        _service.Lock(record.Id, Password);

        Assert.Throws<FolderLockException>(() => _service.Unlock(record.Id, "nope"));
    }

    [Fact]
    public void ChangePassword_RejectedWhileEncryptedAndLocked()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);
        _service.Lock(record.Id, Password);

        Assert.Throws<FolderLockException>(() => _service.ChangePassword(record.Id, Password, "new"));
    }

    [Fact]
    public void ChangePassword_BeforeLocking_UsesNewPasswordForVault()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out var recoveryCode);
        _service.ChangePassword(record.Id, Password, "new-pass");

        _service.Lock(record.Id, "new-pass");
        _service.Unlock(record.Id, recoveryCode!);

        Assert.Equal("secret content", File.ReadAllText(Path.Combine(_folder, "data.txt")));
    }

    [Fact]
    public async Task LockAsync_Cancelled_LeavesFolderIntactAndUnlocked()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.LockAsync(record.Id, Password, progress: null, cts.Token));

        Assert.True(Directory.Exists(_folder));
        Assert.False(_service.GetAll().Single().IsLocked);
    }

    [Fact]
    public async Task UnlockAsync_Cancelled_KeepsVaultAndLockedState()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);
        _service.Lock(record.Id, Password);
        var vaultPath = _service.GetAll().Single().VaultPath!;

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.UnlockAsync(record.Id, Password, progress: null, cts.Token));

        Assert.True(File.Exists(vaultPath));
        Assert.True(_service.GetAll().Single().IsLocked);
        Assert.False(Directory.Exists(_folder));
    }

    [Fact]
    public void LockEncrypted_WhenSourceCannotBeErased_KeepsVaultAndMarksLocked()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);

        // 允许加密读取，但禁止擦除（模拟文件被其他程序占用且未共享删除）
        using var hold = new FileStream(
            Path.Combine(_folder, "data.txt"),
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);

        var error = Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, Password));
        Assert.Contains("无法安全擦除", error.Message);

        var loaded = _service.GetAll().Single();
        Assert.True(loaded.IsLocked);
        Assert.NotNull(loaded.VaultPath);
        Assert.True(File.Exists(loaded.VaultPath));

        // 容器必须是完整可用的，绝不能在失败路径里被删掉
        using var secret = new Secret(Password);
        Assert.True(_service.VerifyVault(record.Id, secret));
    }

    [Fact]
    public void LockEncrypted_RetryAfterEraseFailure_RefusesAndDoesNotOverwriteVault()
    {
        var record = _service.Add(_folder, Password, encrypt: true, out _);

        long vaultLength;
        using (var hold = new FileStream(
                   Path.Combine(_folder, "data.txt"),
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read))
        {
            Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, Password));
            var vaultPath = _service.GetAll().Single().VaultPath!;
            vaultLength = new FileInfo(vaultPath).Length;
        }

        var loaded = _service.GetAll().Single();
        Assert.True(loaded.IsLocked);

        Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, Password));
        Assert.Equal(vaultLength, new FileInfo(loaded.VaultPath!).Length);

        using var secret = new Secret(Password);
        Assert.True(_service.VerifyVault(record.Id, secret));
    }

    public void Dispose()
    {
        // 测试收尾必须先恢复 ACL，否则残留的 Deny Everyone 会让后续清理/其他测试失败。
        foreach (var record in _service.GetAll())
        {
            if (!record.IsLocked || record.EncryptionMode == EncryptionMode.Aes256Gcm || record.DaclSddl is null)
            {
                continue;
            }

            try
            {
                new FolderLocker().Unlock(
                    record.Path,
                    new SecurityBackup(
                        record.DaclSddl,
                        record.AccessRulesProtected,
                        record.OwnerSid,
                        record.OriginalAttributes));
            }
            catch
            {
            }
        }

        try
        {
            if (Directory.Exists(_root))
            {
                File.SetAttributes(_root, FileAttributes.Normal);
            }

            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }
}
