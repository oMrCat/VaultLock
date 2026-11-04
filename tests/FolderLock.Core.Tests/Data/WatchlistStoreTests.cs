using FolderLock.Core.Data;
using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Data;

public sealed class WatchlistStoreTests : IDisposable
{
    private readonly string _root;

    public WatchlistStoreTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [Fact]
    public void Save_WritesAtomicallyAndRoundTrips()
    {
        var path = Path.Combine(_root, "watchlist.json");
        var store = new WatchlistStore(path);

        store.Save(new[] { @"C:\One", @"C:\Two", @"C:\One" });

        var entries = store.Load();
        Assert.Equal(new[] { @"C:\One", @"C:\Two" }, entries);

        var leftovers = Directory.GetFiles(_root, "*.tmp");
        Assert.Empty(leftovers);
    }

    [Fact]
    public void Save_ThrowsWhenTargetCannotBeReplaced()
    {
        var path = Path.Combine(_root, "watchlist.json");
        Directory.CreateDirectory(path);

        var store = new WatchlistStore(path);

        Assert.Throws<WatchlistWriteException>(() => store.Save(new[] { @"C:\One" }));
    }

    [Fact]
    public void TryLoad_ReportsCorruptJsonInsteadOfSilentlyReturningEmpty()
    {
        var path = Path.Combine(_root, "watchlist.json");
        File.WriteAllText(path, "{not-json");

        var store = new WatchlistStore(path);

        Assert.False(store.TryLoad(out var entries, out var error));
        Assert.Empty(entries);
        Assert.False(string.IsNullOrWhiteSpace(error));
        Assert.Throws<WatchlistReadException>(() => store.Load());
    }

    [Fact]
    public void TryValidate_AcceptsUserOwnedFolderAndRejectsMissingPath()
    {
        var folder = Path.Combine(_root, "Owned");
        Directory.CreateDirectory(folder);

        Assert.True(WatchlistEntryValidator.TryValidate(folder, out _));

        var missing = Path.Combine(_root, "Missing");
        Assert.False(WatchlistEntryValidator.TryValidate(missing, out var reason));
        Assert.Contains("不存在", reason);
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
