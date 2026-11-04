using System.Text.Json;
using FolderLock.Core.Util;

namespace FolderLock.Core.Data;

public sealed class WatchlistReadException : Exception
{
    public WatchlistReadException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

public sealed class WatchlistWriteException : Exception
{
    public WatchlistWriteException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

public sealed class WatchlistStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private readonly string _path;

    public WatchlistStore(string? path = null)
    {
        _path = path ?? GetDefaultPath();
    }

    public string Path => _path;

    public static string GetDefaultPath()
    {
        if (AppPaths.IsPortable)
        {
            return System.IO.Path.Combine(AppPaths.DataDirectory, "watchlist.json");
        }

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return System.IO.Path.Combine(programData, "FolderLock", "watchlist.json");
    }

    public IReadOnlyList<string> Load()
    {
        if (!TryLoad(out var entries, out var error))
        {
            throw new WatchlistReadException(error!, new IOException(error));
        }

        return entries;
    }

    public bool TryLoad(out IReadOnlyList<string> entries, out string? error)
    {
        entries = Array.Empty<string>();
        error = null;

        try
        {
            if (!File.Exists(_path))
            {
                return true;
            }

            var json = File.ReadAllText(_path);
            entries = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
            return true;
        }
        catch (Exception ex)
        {
            error = $"无法读取监控列表 {_path}：{ex.Message}";
            return false;
        }
    }

    public void Save(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var payload = JsonSerializer.Serialize(
            paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Options);

        try
        {
            AtomicFile.WriteAllText(_path, payload);
        }
        catch (Exception ex)
        {
            throw new WatchlistWriteException($"无法写入监控列表 {_path}：{ex.Message}", ex);
        }
    }
}
