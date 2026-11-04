using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class FolderLockerStateTests : IDisposable
{
    private readonly string _root;
    private readonly string _folder;
    private readonly FolderLocker _locker = new();

    public FolderLockerStateTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Vault");
        Directory.CreateDirectory(_folder);
    }

    [Fact]
    public void GetLockState_TransitionsBetweenUnlockedAndLocked()
    {
        Assert.Equal(FolderLockState.Unlocked, _locker.GetLockState(_folder));

        var backup = _locker.Lock(_folder);
        Assert.Equal(FolderLockState.Locked, _locker.GetLockState(_folder));
        Assert.True(_locker.IsLocked(_folder));

        _locker.Unlock(_folder, backup);
        Assert.Equal(FolderLockState.Unlocked, _locker.GetLockState(_folder));
        Assert.False(_locker.IsLocked(_folder));
    }

    [Fact]
    public void LockThenUnlock_RestoresOriginalHiddenAndSystemAttributes()
    {
        File.SetAttributes(_folder, FileAttributes.Hidden);
        var original = (uint)File.GetAttributes(_folder);

        var backup = _locker.Lock(_folder);
        Assert.Equal(original, backup.OriginalAttributes);

        _locker.Unlock(_folder, backup);

        var restored = File.GetAttributes(_folder);
        Assert.True(restored.HasFlag(FileAttributes.Hidden));
        Assert.False(restored.HasFlag(FileAttributes.System));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_folder))
            {
                File.SetAttributes(_folder, FileAttributes.Normal);
            }

            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }
}
