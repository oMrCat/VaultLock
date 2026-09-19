using System.IO;
using System.Text.Json;

namespace FolderLock.App;

public sealed class AppSettings
{
    public string Theme { get; set; } = "System";

    public double WindowWidth { get; set; } = 1120;

    public double WindowHeight { get; set; } = 700;

    public double WindowLeft { get; set; } = double.NaN;

    public double WindowTop { get; set; } = double.NaN;

    public bool WindowMaximized { get; set; }

    public bool AutoLockOnSessionLock { get; set; } = true;

    public int AutoLockIdleMinutes { get; set; }

    public int AutoRelockMinutes { get; set; } = 10;

    public bool PanicHotkeyEnabled { get; set; } = true;

    public bool CachePasswords { get; set; } = true;

    public string Language { get; set; } = "System";

    public bool WindowsHello { get; set; }

    public string UpdateUrl { get; set; } = string.Empty;

    public static AppSettings Current { get; } = Load();

    public string ExecutableHash { get; set; } = string.Empty;

    private static string GetFilePath()
    {
        return Path.Combine(FolderLock.Core.Data.AppPaths.DataDirectory, "settings.json");
    }

    private static AppSettings Load()
    {
        try
        {
            var path = GetFilePath();
            if (File.Exists(path))
            {
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path)) ?? new AppSettings();
            }
        }
        catch
        {
        }

        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            var path = GetFilePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
        }
    }
}
