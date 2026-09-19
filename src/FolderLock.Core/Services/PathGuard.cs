namespace FolderLock.Core.Services;

public static class PathGuard
{
    public static bool TryGetBlockReason(string path, out string reason)
    {
        reason = string.Empty;

        if (string.IsNullOrWhiteSpace(path))
        {
            reason = "路径为空。";
            return true;
        }

        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        var separator = Path.DirectorySeparatorChar;

        var root = Path.GetPathRoot(full);
        if (!string.IsNullOrEmpty(root) &&
            string.Equals(Path.TrimEndingDirectorySeparator(root), full, StringComparison.OrdinalIgnoreCase))
        {
            reason = "不能锁定驱动器根目录。";
            return true;
        }

        foreach (var item in GetProtectedFolders())
        {
            if (string.Equals(item, full, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"不能锁定系统或用户重要目录：{item}";
                return true;
            }

            if (item.StartsWith(full + separator, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"该文件夹包含受保护目录（{item}），不宜整体锁定。";
                return true;
            }

            if (IsSystemArea(item) && full.StartsWith(item + separator, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"不能锁定系统目录内的文件夹：{item}";
                return true;
            }
        }

        return false;
    }

    public static void EnsureLockable(string path)
    {
        if (TryGetBlockReason(path, out var reason))
        {
            throw new FolderLockException(reason);
        }
    }

    private static bool IsSystemArea(string folder)
    {
        return string.Equals(folder, GetFolder(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)
               || string.Equals(folder, GetFolder(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase)
               || string.Equals(folder, GetFolder(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase)
               || string.Equals(folder, GetFolder(Environment.SpecialFolder.CommonApplicationData), StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> GetProtectedFolders()
    {
        var folders = new[]
        {
            Environment.SpecialFolder.Windows,
            Environment.SpecialFolder.ProgramFiles,
            Environment.SpecialFolder.ProgramFilesX86,
            Environment.SpecialFolder.CommonApplicationData,
            Environment.SpecialFolder.ApplicationData,
            Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolder.UserProfile,
            Environment.SpecialFolder.DesktopDirectory,
            Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.MyPictures,
            Environment.SpecialFolder.MyMusic,
            Environment.SpecialFolder.MyVideos,
            Environment.SpecialFolder.Favorites,
        };

        foreach (var folder in folders)
        {
            var value = GetFolder(folder);
            if (!string.IsNullOrWhiteSpace(value))
            {
                yield return Path.TrimEndingDirectorySeparator(value);
            }
        }
    }

    private static string GetFolder(Environment.SpecialFolder folder)
    {
        try
        {
            return Environment.GetFolderPath(folder);
        }
        catch
        {
            return string.Empty;
        }
    }
}
