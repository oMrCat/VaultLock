namespace FolderLock.Core.Integration;

public enum OverlayKind
{
    None = 0,
    Locked = 1,
}

public static class OverlayAdvisor
{
    public static OverlayKind GetOverlay(string path, IEnumerable<string> lockedFolders)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(lockedFolders);

        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var separator = Path.DirectorySeparatorChar;

        foreach (var folder in lockedFolders)
        {
            if (string.IsNullOrWhiteSpace(folder))
            {
                continue;
            }

            var protectedFolder = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder));

            if (string.Equals(protectedFolder, full, StringComparison.OrdinalIgnoreCase))
            {
                return OverlayKind.Locked;
            }

            if (full.StartsWith(protectedFolder + separator, StringComparison.OrdinalIgnoreCase))
            {
                return OverlayKind.Locked;
            }
        }

        return OverlayKind.None;
    }

    public static OverlayKind GetOverlayForWatchlist(string path, Data.WatchlistStore watchlist)
    {
        ArgumentNullException.ThrowIfNull(watchlist);
        return GetOverlay(path, watchlist.Load());
    }
}
