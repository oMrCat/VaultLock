namespace FolderLock.Core.Services;

public static class DiskSpace
{
    private const long SafetyMargin = 64L * 1024 * 1024;

    public static long GetDirectorySize(string path)
    {
        if (!Directory.Exists(path))
        {
            return 0;
        }

        long total = 0;
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                total += new FileInfo(file).Length;
            }
            catch
            {
            }
        }

        return total;
    }

    public static void EnsureRoomFor(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full);
        if (string.IsNullOrEmpty(root))
        {
            return;
        }

        var size = GetDirectorySize(full);
        EnsureRoomForBytes(full, size);
    }

    public static void EnsureRoomForBytes(string pathOnDrive, long bytes)
    {
        if (bytes <= 0)
        {
            return;
        }

        var root = Path.GetPathRoot(Path.GetFullPath(pathOnDrive));
        if (string.IsNullOrEmpty(root))
        {
            return;
        }

        long available;
        try
        {
            available = new DriveInfo(root).AvailableFreeSpace;
        }
        catch
        {
            return;
        }

        if (available < bytes + SafetyMargin)
        {
            throw new FolderLockException(
                $"磁盘可用空间不足：需要约 {Format(bytes)}，可用 {Format(available)}。请清理空间后重试。");
        }
    }

    private static string Format(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.#} {units[unit]}";
    }
}
