using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public sealed class FolderServiceTests : IDisposable
{
    private const string Password = "s3cret-pass";

    private readonly string _root;
    private readonly string _folder;
    private readonly FolderService _service;

    public FolderServiceTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Vault");
        Directory.CreateDirectory(_folder);
        File.WriteAllText(Path.Combine(_folder, "data.txt"), "content");

        var dbPath = Path.Combine(_root, "folderlock.db");
        _service = new FolderService(new FolderStore(dbPath), new FolderLocker());
    }

    [Fact]
    public void Add_StoresHashedPasswordAndReturnsRecord()
    {
        var record = _service.Add(_folder, Password);

        Assert.True(record.Id > 0);
        Assert.Equal("Vault", record.DisplayName);
        Assert.NotNull(record.PasswordHash);
        Assert.DoesNotContain(Password, record.PasswordHash!);
        Assert.False(record.IsLocked);
    }

    [Fact]
    public void Add_RejectsDuplicateFolder()
    {
        _service.Add(_folder, Password);

        Assert.Throws<FolderLockException>(() => _service.Add(_folder, Password));
    }

    [Fact]
    public void Add_RejectsMissingFolder()
    {
        Assert.Throws<FolderLockException>(() => _service.Add(Path.Combine(_root, "nope"), Password));
    }

    [Fact]
    public void LockAndUnlock_RoundTripsWithCorrectPassword()
    {
        var record = _service.Add(_folder, Password);

        _service.Lock(record.Id, Password);
        Assert.True(_service.GetAll().Single().IsLocked);
        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(Path.Combine(_folder, "data.txt")));

        _service.Unlock(record.Id, Password);
        Assert.False(_service.GetAll().Single().IsLocked);
        Assert.Equal("content", File.ReadAllText(Path.Combine(_folder, "data.txt")));
    }

    [Fact]
    public void Lock_RejectsWrongPassword()
    {
        var record = _service.Add(_folder, Password);

        Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, "wrong"));
    }

    [Fact]
    public void Unlock_RejectsWrongPassword()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);

        Assert.Throws<FolderLockException>(() => _service.Unlock(record.Id, "wrong"));
    }

    [Fact]
    public void Lock_RejectsAlreadyLocked()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);

        Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, Password));
    }

    [Fact]
    public void ChangePassword_RequiresOldPassword()
    {
        var record = _service.Add(_folder, Password);
        _service.ChangePassword(record.Id, Password, "new-pass");

        Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, Password));
        _service.Lock(record.Id, "new-pass");
        Assert.True(_service.GetAll().Single().IsLocked);
    }

    [Fact]
    public void Remove_RequiresUnlockedAndCorrectPassword()
    {
        var record = _service.Add(_folder, Password);

        _service.Remove(record.Id, Password);
        Assert.Empty(_service.GetAll());
    }

    [Fact]
    public void Remove_RejectsWhileLocked()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);

        Assert.Throws<FolderLockException>(() => _service.Remove(record.Id, Password));
    }

    public void Dispose()
    {
        foreach (var record in _service.GetAll())
        {
            if (record.IsLocked && record.DaclSddl is not null)
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
