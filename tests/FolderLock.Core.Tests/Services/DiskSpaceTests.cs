using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public sealed class DiskSpaceTests : IDisposable
{
    private readonly string _root;

    public DiskSpaceTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        File.WriteAllBytes(Path.Combine(_root, "big.bin"), new byte[100_000]);
    }

    [Fact]
    public void GetDirectorySize_SumsFiles()
    {
        Assert.Equal(100_000, DiskSpace.GetDirectorySize(_root));
    }

    [Fact]
    public void EnsureRoomFor_TempFolderDoesNotThrow()
    {
        DiskSpace.EnsureRoomFor(_root);
    }

    [Fact]
    public void EnsureRoomForBytes_SmallAmountDoesNotThrow()
    {
        DiskSpace.EnsureRoomForBytes(_root, 1024);
    }

    [Fact]
    public void EnsureRoomForBytes_ImpossibleAmountThrows()
    {
        Assert.Throws<FolderLockException>(() => DiskSpace.EnsureRoomForBytes(_root, long.MaxValue / 2));
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
}
