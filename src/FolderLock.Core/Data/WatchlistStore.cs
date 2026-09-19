using System.Text.Json;

namespace FolderLock.Core.Data;

public sealed class WatchlistStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private readonly string _path;

    public WatchlistStore(string? path = null)
    {
        _path = path ?? GetDefaultPath();
    }

    public static string GetDefaultPath()
    {
        if (AppPaths.IsPortable)
        {
            return Path.Combine(AppPaths.DataDirectory, "watchlist.json");
        }

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(programData, "FolderLock", "watchlist.json");
    }

    public IReadOnlyList<string> Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<string>();
            }

            var json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    public void Save(IEnumerable<string> paths)
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var payload = JsonSerializer.Serialize(paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), Options);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, payload);
        File.Move(temp, _path, overwrite: true);
    }
}
