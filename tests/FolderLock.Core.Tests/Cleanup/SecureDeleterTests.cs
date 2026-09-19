using System.Text;
using FolderLock.Core.Cleanup;
using Microsoft.Win32;

namespace FolderLock.Core.Tests.Cleanup;

public sealed class SecureDeleterTests : IDisposable
{
    private readonly string _root;
    private readonly SecureDeleter _deleter = new();

    public SecureDeleterTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [Fact]
    public void DeleteFile_RemovesFile()
    {
        var file = Path.Combine(_root, "secret.txt");
        File.WriteAllText(file, "sensitive");

        _deleter.DeleteFile(file);

        Assert.False(File.Exists(file));
        Assert.Empty(Directory.GetFiles(_root));
    }

    [Fact]
    public void DeleteFile_ClearsReadOnlyAndHidden()
    {
        var file = Path.Combine(_root, "ro.txt");
        File.WriteAllText(file, "data");
        File.SetAttributes(file, FileAttributes.ReadOnly | FileAttributes.Hidden);

        _deleter.DeleteFile(file);

        Assert.False(File.Exists(file));
    }

    [Fact]
    public void DeleteDirectory_RemovesTree()
    {
        var nested = Path.Combine(_root, "a", "b");
        Directory.CreateDirectory(nested);
        File.WriteAllText(Path.Combine(_root, "a", "one.txt"), "one");
        File.WriteAllText(Path.Combine(nested, "two.txt"), "two");

        _deleter.DeleteDirectory(_root);

        Assert.False(Directory.Exists(_root));
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

public sealed class TraceCleanerTests : IDisposable
{
    private readonly string _root;

    public TraceCleanerTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [Fact]
    public void RemoveRecentItems_DeletesOnlyMatchingShortcuts()
    {
        var target = @"C:\Secrets\Hidden";
        var matching = Path.Combine(_root, "match.lnk");
        var other = Path.Combine(_root, "other.lnk");
        File.WriteAllBytes(matching, Encoding.Unicode.GetBytes($@"{target}\file.txt"));
        File.WriteAllText(other, "unrelated content");

        var removed = TraceCleaner.RemoveRecentItems(new[] { _root }, target);

        Assert.Equal(1, removed);
        Assert.False(File.Exists(matching));
        Assert.True(File.Exists(other));
    }

    [Fact]
    public void RemoveRegistryMatches_RemovesMatchingValuesAndMruList()
    {
        var target = @"C:\Secrets\Hidden";
        var subKey = $@"Software\FolderLockTests\{Guid.NewGuid():N}";
        using (var key = Registry.CurrentUser.CreateSubKey(subKey)!)
        {
            key.SetValue("0", $@"{target}\a.txt");
            key.SetValue("1", @"C:\Other\b.txt");
            key.SetValue("MRUListEx", new byte[] { 0, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF });
        }

        try
        {
            var removed = TraceCleaner.RemoveRegistryMatches(Registry.CurrentUser, subKey, target);

            Assert.Equal(1, removed);
            using var verify = Registry.CurrentUser.OpenSubKey(subKey)!;
            Assert.Null(verify.GetValue("0"));
            Assert.NotNull(verify.GetValue("1"));
            Assert.Null(verify.GetValue("MRUListEx"));
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
        }
    }

    [Fact]
    public void RemoveRegistryMatches_ReturnsZeroForMissingKey()
    {
        var removed = TraceCleaner.RemoveRegistryMatches(
            Registry.CurrentUser,
            $@"Software\FolderLockTests\{Guid.NewGuid():N}",
            @"C:\Nothing");

        Assert.Equal(0, removed);
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
