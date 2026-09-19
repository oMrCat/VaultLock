using FolderLock.Core.Data;

namespace FolderLock.Core.Tests.Data;

public sealed class FolderStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly FolderStore _store;

    public FolderStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"), "test.db");
        _store = new FolderStore(_dbPath);
        _store.Initialize();
    }

    [Fact]
    public void Insert_AssignsIdAndRoundTrips()
    {
        var record = new FolderRecord
        {
            Path = @"C:\Data\Secrets",
            DisplayName = "Secrets",
            PasswordHash = "PBKDF2-SHA256$1000$c2FsdA==$aGFzaA==",
        };

        _store.Insert(record);

        Assert.True(record.Id > 0);
        var loaded = _store.GetById(record.Id);
        Assert.NotNull(loaded);
        Assert.Equal(record.Path, loaded!.Path);
        Assert.Equal(record.DisplayName, loaded.DisplayName);
        Assert.Equal(record.PasswordHash, loaded.PasswordHash);
        Assert.False(loaded.IsLocked);
    }

    [Fact]
    public void GetByPath_IsCaseInsensitive()
    {
        _store.Insert(new FolderRecord { Path = @"C:\Data\Secrets", DisplayName = "Secrets" });

        Assert.NotNull(_store.GetByPath(@"c:\data\secrets"));
    }

    [Fact]
    public void Update_PersistsLockStateAndBackup()
    {
        var record = _store.Insert(new FolderRecord { Path = @"C:\Data\Secrets", DisplayName = "Secrets" });

        record.IsLocked = true;
        record.DaclSddl = "D:PAI(A;;FA;;;WD)";
        record.AccessRulesProtected = true;
        record.LastLockedAt = DateTimeOffset.UtcNow;
        _store.Update(record);

        var loaded = _store.GetById(record.Id)!;
        Assert.True(loaded.IsLocked);
        Assert.Equal("D:PAI(A;;FA;;;WD)", loaded.DaclSddl);
        Assert.True(loaded.AccessRulesProtected);
        Assert.NotNull(loaded.LastLockedAt);
    }

    [Fact]
    public void Insert_DuplicatePathThrows()
    {
        _store.Insert(new FolderRecord { Path = @"C:\Data\Secrets", DisplayName = "Secrets" });

        Assert.ThrowsAny<Exception>(() =>
            _store.Insert(new FolderRecord { Path = @"C:\Data\Secrets", DisplayName = "Secrets" }));
    }

    [Fact]
    public void GetAll_ReturnsSortedByDisplayName()
    {
        _store.Insert(new FolderRecord { Path = @"C:\Data\Zeta", DisplayName = "Zeta" });
        _store.Insert(new FolderRecord { Path = @"C:\Data\Alpha", DisplayName = "Alpha" });

        var all = _store.GetAll();

        Assert.Equal(2, all.Count);
        Assert.Equal("Alpha", all[0].DisplayName);
        Assert.Equal("Zeta", all[1].DisplayName);
    }

    [Fact]
    public void Delete_RemovesRecord()
    {
        var record = _store.Insert(new FolderRecord { Path = @"C:\Data\Secrets", DisplayName = "Secrets" });

        _store.Delete(record.Id);

        Assert.Null(_store.GetById(record.Id));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path.GetDirectoryName(_dbPath)!, recursive: true);
        }
        catch
        {
        }
    }
}
