using FolderLock.Core.Security;
using FolderLock.Service;

var mode = ServiceSignaturePolicy.CurrentMode;
ServiceLog.Write(ServiceSignatureGuard.InfoLevel, $"当前模式：{ServiceSignaturePolicy.Describe(mode)}。");

var exePath = Environment.ProcessPath;
var check = exePath is null
    ? new AuthenticodeCheck(AuthenticodeStatus.Error, null, PublisherTrust.NotConfigured, "无法确定可执行文件路径。")
    : AuthenticodePolicy.Check(exePath);

var decision = ServiceSignatureGuard.Evaluate(check, mode);
ServiceLog.Write(decision.Level, decision.Message);

if (decision.IsRefused)
{
    Console.Error.WriteLine(decision.Message);

    if (!Environment.UserInteractive)
    {
        // 由 SCM 启动（非交互）时直接失败退出，让服务管理器显示启动失败。
        Environment.Exit(1);
    }
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "FolderLockGuard");
builder.Services.AddHostedService<WatchdogWorker>();

var host = builder.Build();
host.Run();
