using System.Text;
using Microsoft.Win32;

namespace FolderLock.Core.Cleanup;

public sealed class TraceCleanResult
{
    public int ShortcutsRemoved { get; set; }

    public int RegistryValuesRemoved { get; set; }

    public int CacheFilesRemoved { get; set; }

    public List<string> Notes { get; } = new();
}

public sealed class TraceCleaner
{
    private static readonly string[] RecentItemExtensions =
    {
        ".lnk",
        ".automaticDestinations-ms",
        ".customDestinations-ms",
    };

    private static readonly string[] RegistryTargets =
    {
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",
    };

    public TraceCleanResult Clean(string folderPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folderPath);

        var path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folderPath));
        var result = new TraceCleanResult();

        result.ShortcutsRemoved = RemoveRecentItems(GetRecentDirectories(), path);
        result.RegistryValuesRemoved = CleanRegistry(path);
        result.CacheFilesRemoved = CleanCaches(result);

        return result;
    }

    public static int RemoveRecentItems(IEnumerable<string> directories, string folderPath)
    {
        var removed = 0;
        foreach (var directory in directories)
        {
            if (!Directory.Exists(directory))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(directory))
            {
                if (!RecentItemExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    if (FileContainsPath(file, folderPath))
                    {
                        File.Delete(file);
                        removed++;
                    }
                }
                catch
                {
                }
            }
        }

        return removed;
    }

    public static int RemoveRegistryMatches(RegistryKey root, string subKeyPath, string folderPath)
    {
        var removed = 0;

        using var key = root.OpenSubKey(subKeyPath, writable: true);
        if (key is null)
        {
            return 0;
        }

        var matching = new List<string>();
        foreach (var name in key.GetValueNames())
        {
            if (IsMruListValue(name))
            {
                continue;
            }

            if (ValueMatches(key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames), folderPath))
            {
                matching.Add(name);
            }
        }

        foreach (var name in matching)
        {
            try
            {
                key.DeleteValue(name, throwOnMissingValue: false);
                removed++;
            }
            catch
            {
            }
        }

        if (matching.Count > 0)
        {
            foreach (var name in key.GetValueNames())
            {
                if (IsMruListValue(name))
                {
                    try
                    {
                        key.DeleteValue(name, throwOnMissingValue: false);
                    }
                    catch
                    {
                    }
                }
            }
        }

        foreach (var child in key.GetSubKeyNames())
        {
            removed += RemoveRegistryMatches(root, $@"{subKeyPath}\{child}", folderPath);
        }

        return removed;
    }

    private static int CleanRegistry(string folderPath)
    {
        var removed = 0;
        foreach (var target in RegistryTargets)
        {
            removed += RemoveRegistryMatches(Registry.CurrentUser, target, folderPath);
        }

        return removed;
    }

    private static int CleanCaches(TraceCleanResult result)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var explorer = Path.Combine(localAppData, "Microsoft", "Windows", "Explorer");
        var removed = 0;
        var locked = 0;

        foreach (var pattern in new[] { "thumbcache_*.db", "iconcache_*.db" })
        {
            if (!Directory.Exists(explorer))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(explorer, pattern))
            {
                try
                {
                    File.Delete(file);
                    removed++;
                }
                catch
                {
                    locked++;
                }
            }
        }

        var iconCache = Path.Combine(localAppData, "IconCache.db");
        try
        {
            if (File.Exists(iconCache))
            {
                File.Delete(iconCache);
                removed++;
            }
        }
        catch
        {
            locked++;
        }

        if (locked > 0)
        {
            result.Notes.Add($"有 {locked} 个缩略图/图标缓存文件被系统占用，未能删除（可重启后由工具再次清理）。");
        }

        return removed;
    }

    private static IEnumerable<string> GetRecentDirectories()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var recent = Path.Combine(appData, "Microsoft", "Windows", "Recent");
        yield return recent;
        yield return Path.Combine(recent, "AutomaticDestinations");
        yield return Path.Combine(recent, "CustomDestinations");
    }

    private static bool IsMruListValue(string name) =>
        string.Equals(name, "MRUListEx", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, "MRUList", StringComparison.OrdinalIgnoreCase);

    private static bool ValueMatches(object? value, string folderPath)
    {
        switch (value)
        {
            case string text:
                return text.Contains(folderPath, StringComparison.OrdinalIgnoreCase);
            case string[] strings:
                return strings.Any(s => s.Contains(folderPath, StringComparison.OrdinalIgnoreCase));
            case byte[] bytes:
                return BytesContainPath(bytes, folderPath);
            default:
                return false;
        }
    }

    private static bool FileContainsPath(string file, string folderPath)
    {
        try
        {
            var bytes = File.ReadAllBytes(file);
            return BytesContainPath(bytes, folderPath);
        }
        catch
        {
            return false;
        }
    }

    private static bool BytesContainPath(byte[] data, string folderPath)
    {
        if (data.Length == 0 || string.IsNullOrEmpty(folderPath))
        {
            return false;
        }

        return IndexOf(data, Encoding.Unicode.GetBytes(folderPath)) >= 0
               || IndexOf(data, Encoding.UTF8.GetBytes(folderPath)) >= 0
               || IndexOf(data, Encoding.Default.GetBytes(folderPath)) >= 0;
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
        {
            return -1;
        }

        var first = needle[0];
        var limit = haystack.Length - needle.Length;
        for (var i = 0; i <= limit; i++)
        {
            if (haystack[i] != first)
            {
                continue;
            }

            var match = true;
            for (var j = 1; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i;
            }
        }

        return -1;
    }
}
