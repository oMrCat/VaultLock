using FolderLock.Core.Data;

namespace FolderLock.Service;

/// <summary>
/// 服务启动阶段的自校验结论与监控列表读取结果需要可追溯：
/// 便携模式写 exe 目录下的 data\service.log，正式安装写 %ProgramData%\FolderLock\service.log。
/// </summary>
internal static class ServiceLog
{
    public static void Write(string level, string message)
    {
        try
        {
            var directory = AppPaths.IsPortable
                ? AppPaths.DataDirectory
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FolderLock");

            Directory.CreateDirectory(directory);
            File.AppendAllText(
                Path.Combine(directory, "service.log"),
                $"{DateTimeOffset.Now:O} [{level}] {message}{Environment.NewLine}");
        }
        catch
        {
            // 日志失败不能影响服务本身。
        }
    }
}
