using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public sealed class FolderServiceAclDefenseTests : IDisposable
{
    private const string Password = "s3cret-pass";

    private readonly string _root;
    private readonly string _folder;
    private readonly FolderStore _store;
    private readonly FakeLocker _locker = new();
    private readonly FolderService _service;

    public FolderServiceAclDefenseTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Vault");
        Directory.CreateDirectory(_folder);
        File.WriteAllText(Path.Combine(_folder, "data.txt"), "content");

        _store = new FolderStore(Path.Combine(_root, "folderlock.db"));
        _service = new FolderService(_store, _locker, watchlist: new WatchlistStore(Path.Combine(_root, "watchlist.json")));
    }

    [Fact]
    public void Unlock_ReturnsStructuredRecoveryGuidanceWhenOwnershipTakenOver()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);

        _locker.ThrowOnUnlock = true;

        var error = Assert.Throws<FolderLockException>(() => _service.Unlock(record.Id, Password));

        Assert.Contains("所有权", error.Message);
        Assert.Contains("takeown", error.Message);
        Assert.Contains("icacls", error.Message);
        Assert.Contains("S-1-5-21-DEMO", error.Message);
    }

    [Fact]
    public void Lock_FailsCleanlyWhenWriteDacMissing()
    {
        var record = _service.Add(_folder, Password);
        _locker.ThrowOnCapture = true;

        var error = Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, Password));

        Assert.Contains("WRITE_DAC", error.Message);
        Assert.False(_service.GetAll().Single().IsLocked);
    }

    [Fact]
    public void SyncLockStates_KeepsRecordWhenStateUnknown()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);

        _locker.State = FolderLockState.Unknown;
        _service.SyncLockStates();

        Assert.True(_service.GetAll().Single().IsLocked);
        Assert.Contains(_folder, _service.LastUnknownPaths);
    }

    [Fact]
    public void SyncLockStates_MarksUnlockedWhenAclChangedExternally()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);

        _locker.State = FolderLockState.Unlocked;
        _service.SyncLockStates();

        Assert.False(_service.GetAll().Single().IsLocked);
        Assert.Empty(_service.LastUnknownPaths);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }

    private sealed class FakeLocker : IFolderLocker
    {
        public FolderLockState State { get; set; } = FolderLockState.Unlocked;

        public bool ThrowOnCapture { get; set; }

        public bool ThrowOnUnlock { get; set; }

        public SecurityBackup CaptureBackup(string path)
        {
            if (ThrowOnCapture)
            {
                throw new FolderLockAccessException(
                    $"当前进程对目录“{path}”没有 WRITE_DAC 权限（目录所有者：S-1-5-21-DEMO），已拒绝加锁。");
            }

            return new SecurityBackup("D:AI", true, "S-1-5-21-DEMO", 0);
        }

        public void ApplyLock(string path, SecurityBackup backup)
        {
        }

        public SecurityBackup Lock(string path) => CaptureBackup(path);

        public void Unlock(string path, SecurityBackup backup)
        {
            if (ThrowOnUnlock)
            {
                throw new FolderLockAccessException("当前进程没有 WRITE_DAC，或目录所有权已被接管。");
            }
        }

        public FolderLockState GetLockState(string path) => State;

        public bool IsLocked(string path) => GetLockState(path) == FolderLockState.Locked;
    }
}
