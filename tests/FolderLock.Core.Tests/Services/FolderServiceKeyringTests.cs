using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public sealed class FolderServiceKeyringTests : IDisposable
{
    private const string Password = "lock-all-pass";

    private readonly string _root;
    private readonly FolderService _service;

    public FolderServiceKeyringTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _service = new FolderService(new FolderStore(Path.Combine(_root, "db.sqlite")), new FolderLocker());
    }

    private FolderRecord MakeFolder(string name)
    {
        var path = Path.Combine(_root, name);
        Directory.CreateDirectory(path);
        File.WriteAllText(Path.Combine(path, "a.txt"), "x");
        return _service.Add(path, Password);
    }

    [Fact]
    public void LockAll_LocksEveryFolderWithCachedSecret()
    {
        var first = MakeFolder("one");
        var second = MakeFolder("two");
        using var keyring = new Keyring();
        using (var a = new Secret(Password))
        using (var b = new Secret(Password))
        {
            keyring.Store(first.Id, a);
            keyring.Store(second.Id, b);
        }

        var locked = _service.LockAll(keyring);

        Assert.Equal(2, locked.Count);
        Assert.All(_service.GetAll(), record => Assert.True(record.IsLocked));
        Assert.Equal(0, keyring.Count);

        _service.Unlock(second.Id, Password);
        Assert.False(_service.GetAll().Single(r => r.Id == second.Id).IsLocked);
    }

    [Fact]
    public void LockAll_SkipsFoldersWithoutCachedSecret()
    {
        var first = MakeFolder("one");
        MakeFolder("two");
        using var keyring = new Keyring();
        using (var secret = new Secret(Password))
        {
            keyring.Store(first.Id, secret);
        }

        var locked = _service.LockAll(keyring);

        Assert.Single(locked);
        Assert.True(_service.GetAll().Single(r => r.Id == first.Id).IsLocked);
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
                    new FolderLocker().Unlock(record.Path, new SecurityBackup(record.DaclSddl, record.AccessRulesProtected));
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
