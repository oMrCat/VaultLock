using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace FolderLock.App;

public static class ServiceRegistration
{
    public const string ServiceName = "FolderLockGuard";
    private const string DisplayName = "FolderLock 守护服务";

    public static bool IsInstalled()
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
        return key is not null;
    }

    public static string? FindServiceExecutable()
    {
        var appDirectory = Path.GetDirectoryName(Environment.ProcessPath);
        if (string.IsNullOrEmpty(appDirectory))
        {
            return null;
        }

        var candidates = new[]
        {
            Path.Combine(appDirectory, "FolderLock.Service.exe"),
            Path.GetFullPath(Path.Combine(appDirectory, "..", "FolderLock.Service.exe")),
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    public static void InstallElevated() => RunElevated(BuildInstallScript());

    public static void UninstallElevated() => RunElevated(BuildUninstallScript());

    public static void InstallDirect() => RunDirect(BuildInstallScript());

    public static void UninstallDirect() => RunDirect(BuildUninstallScript());

    private static string BuildInstallScript()
    {
        var exe = FindServiceExecutable()
                  ?? throw new InvalidOperationException(
                      "未找到 FolderLock.Service.exe。请先发布服务项目：dotnet publish src\\FolderLock.Service -c Release -r win-x64 --self-contained false，并把生成的 exe 放到主程序同目录。");

        return $"""
            @echo off
            sc.exe create "{ServiceName}" binPath= "{exe}" start= auto DisplayName= "{DisplayName}"
            sc.exe description "{ServiceName}" "监控并自动恢复 FolderLock 的文件夹锁定。"
            sc.exe failure "{ServiceName}" reset= 86400 actions= restart/5000/restart/5000/restart/5000
            sc.exe start "{ServiceName}"
            """;
    }

    private static string BuildUninstallScript() => $"""
        @echo off
        sc.exe stop "{ServiceName}"
        sc.exe delete "{ServiceName}"
        """;

    private static void RunDirect(string script)
    {
        var temp = WriteScript(script);
        try
        {
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c \"{temp}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });

            process?.WaitForExit();
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static void RunElevated(string script)
    {
        var temp = WriteScript(script);

        try
        {
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = temp,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });

            process?.WaitForExit();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("需要管理员权限才能安装/卸载服务，操作已取消。", ex);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static string WriteScript(string script)
    {
        var temp = Path.Combine(Path.GetTempPath(), $"folderlock-svc-{Guid.NewGuid():N}.cmd");
        File.WriteAllText(temp, script.Replace("\r\n", "\n").Replace("\n", "\r\n"));
        return temp;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
        }
    }
}
