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

    /// <summary>是否在锁定后清理系统共享的缩略图/图标缓存（默认关闭，避免影响其它文件夹）。</summary>
    public bool CleanExplorerCaches { get; set; }

    public string Language { get; set; } = "System";

    public bool WindowsHello { get; set; }

    public string UpdateUrl { get; set; } = string.Empty;

    /// <summary>
    /// 更新包是否必须带有效 Authenticode 签名。默认 false：未签名发布下
    /// 完整性由 HTTPS 清单内的 SHA-256（常量时间比较）保证；启用代码签名后
    /// 可在 settings.json 设为 true 加固。
    /// </summary>
    public bool RequireSignedUpdates { get; set; }

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
            FolderLock.Core.Util.AtomicFile.WriteAllText(
                path,
                JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
        }
    }
}
