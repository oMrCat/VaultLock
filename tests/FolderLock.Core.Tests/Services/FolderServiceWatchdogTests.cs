using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public sealed class FolderServiceWatchdogTests : IDisposable
{
    private const string Password = "watchdog-pass";

    private readonly string _root;
    private readonly string _folder;
    private readonly FolderService _service;
    private readonly FolderLocker _locker = new();

    public FolderServiceWatchdogTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Guarded");
        Directory.CreateDirectory(_folder);
        File.WriteAllText(Path.Combine(_folder, "data.txt"), "content");

        _service = new FolderService(new FolderStore(Path.Combine(_root, "folderlock.db")), new FolderLocker());
    }

    [Fact]
    public void EnforceLocks_ReappliesTamperedAclWithoutLosingBackup()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);
        var locked = _service.GetAll().Single();
        var originalBackup = new SecurityBackup(locked.DaclSddl!, locked.AccessRulesProtected);

        _locker.Unlock(_folder, originalBackup);
        Assert.False(_locker.IsLocked(_folder));

        var restored = _service.EnforceLocks();

        Assert.True(restored);
        Assert.True(_locker.IsLocked(_folder));
        Assert.Equal(locked.DaclSddl, _service.GetAll().Single().DaclSddl);

        _service.Unlock(record.Id, Password);
        Assert.Equal("content", File.ReadAllText(Path.Combine(_folder, "data.txt")));
    }

    [Fact]
    public void EnforceLocks_ReturnsFalseWhenNothingToDo()
    {
        Assert.False(_service.EnforceLocks());
    }

    [Fact]
    public void EnforceLocks_IgnoresUnlockedFolders()
    {
        _service.Add(_folder, Password);

        Assert.False(_service.EnforceLocks());
        Assert.False(_locker.IsLocked(_folder));
    }

    public void Dispose()
    {
        foreach (var record in _service.GetAll())
        {
            if (record.IsLocked && record.DaclSddl is not null &&
                record.EncryptionMode != EncryptionMode.Aes256Gcm)
            {
                try
                {
                    _locker.Unlock(record.Path, new SecurityBackup(record.DaclSddl, record.AccessRulesProtected));
                }
                catch
                {
                }
            }
        }

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }
}
