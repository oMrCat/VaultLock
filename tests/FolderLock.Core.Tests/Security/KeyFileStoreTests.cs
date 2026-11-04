using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class KeyFileStoreTests : IDisposable
{
    private readonly string _root;
    private readonly string _path;

    public KeyFileStoreTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _path = Path.Combine(_root, "db.key");
    }

    [Fact]
    public void GetOrCreate_CreatesKeyAndBackupAndReusesIt()
    {
        var first = KeyFileStore.GetOrCreate(_path, bytes => bytes, bytes => bytes);

        Assert.True(File.Exists(_path));
        Assert.True(File.Exists(_path + ".bak"));
        Assert.Equal(32, first.Length);
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));

        var second = KeyFileStore.GetOrCreate(_path, bytes => bytes, bytes => bytes);
        Assert.Equal(first, second);
    }

    [Fact]
    public void GetOrCreate_DoesNotRegenerateCorruptKey()
    {
        File.WriteAllText(_path, "not-base64!!");
        var original = File.ReadAllText(_path);

        var error = Assert.Throws<KeyFileException>(
            () => KeyFileStore.GetOrCreate(_path, bytes => bytes, bytes => bytes));

        Assert.Contains("损坏", error.Message);
        Assert.Equal(original, File.ReadAllText(_path));
    }

    [Fact]
    public void GetOrCreate_ReportsUnprotectFailureWithoutReplacingFile()
    {
        File.WriteAllText(_path, Convert.ToBase64String(new byte[32]));
        var original = File.ReadAllText(_path);

        var error = Assert.Throws<KeyFileException>(
            () => KeyFileStore.GetOrCreate(_path, bytes => bytes, _ => throw new InvalidOperationException("bad dpapi")));

        Assert.Equal(original, File.ReadAllText(_path));
        Assert.Contains("不会自动重建", error.Message);
    }

    [Fact]
    public void GetOrCreate_RejectsShortKeyMaterial()
    {
        File.WriteAllText(_path, Convert.ToBase64String(new byte[16]));

        Assert.Throws<KeyFileException>(() => KeyFileStore.GetOrCreate(_path, bytes => bytes, bytes => bytes));
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
