using FolderLock.Core.Data;
using FolderLock.Core.Security;

namespace FolderLock.Service;

public sealed class WatchdogWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(10);

    private readonly ILogger<WatchdogWorker> _logger;
    private readonly IFolderLocker _locker = new FolderLocker();
    private readonly WatchlistStore _watchlist = new();

    public WatchdogWorker(ILogger<WatchdogWorker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("FolderLock 守护服务已启动。");

        while (!stoppingToken.IsCancellationRequested)
        {
            Enforce();

            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void Enforce()
    {
        foreach (var path in _watchlist.Load())
        {
            try
            {
                if (Directory.Exists(path) && !_locker.IsLocked(path))
                {
                    _locker.Lock(path);
                    _logger.LogWarning("已恢复被解除的锁定：{Path}", path);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "处理 {Path} 时出错。", path);
            }
        }
    }
}
