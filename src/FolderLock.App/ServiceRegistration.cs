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

    public static void InstallElevated() => RunElevated(BuildInstallScript(ServiceName));

    public static void UninstallElevated() => RunElevated(BuildUninstallScript(ServiceName));

    public static void InstallDirect() => RunDirect(BuildInstallScript(ServiceName));

    public static void UninstallDirect() => RunDirect(BuildUninstallScript(ServiceName));

    public static void InstallDirect(string serviceName) => RunDirect(BuildInstallScript(serviceName));

    public static void UninstallDirect(string serviceName) => RunDirect(BuildUninstallScript(serviceName));

    private static string BuildInstallScript(string serviceName)
    {
        var exe = FindServiceExecutable()
                  ?? throw new InvalidOperationException(
                      "未找到 FolderLock.Service.exe。请先运行 installer\\publish.ps1，把服务发布到 artifacts\\publish\\win-x64，并确保与主程序同目录。");

        return $"""
            @echo off
            sc.exe create "{serviceName}" binPath= "\"{exe}\"" start= auto obj= "NT AUTHORITY\LocalService" DisplayName= "{DisplayName}"
            sc.exe description "{serviceName}" "监控并自动恢复 FolderLock 的文件夹锁定（低权限账户运行）。"
            sc.exe failure "{serviceName}" reset= 86400 actions= restart/5000/restart/5000/restart/5000
            sc.exe start "{serviceName}"
            """;
    }

    private static string BuildUninstallScript(string serviceName) => $"""
        @echo off
        sc.exe stop "{serviceName}"
        sc.exe delete "{serviceName}"
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
