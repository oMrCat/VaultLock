using FolderLock.Core.Data;
using FolderLock.Core.Security;

namespace FolderLock.Service;

public sealed class WatchdogWorker : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(10);

    private readonly ILogger<WatchdogWorker> _logger;
    private readonly IFolderLocker _locker = new FolderLocker();
    private readonly WatchlistStore _watchlist = new();
    private bool _watchlistReported;

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
        if (!_watchlist.TryLoad(out var entries, out var loadError))
        {
            _logger.LogWarning("{Error}", loadError);
            return;
        }

        if (!_watchlistReported)
        {
            _watchlistReported = true;
            ServiceLog.Write("信息", $"已读取监控列表：{entries.Count} 条。");
        }

        foreach (var path in entries)
        {
            if (!WatchlistEntryValidator.TryValidate(path, out var reason))
            {
                _logger.LogWarning("跳过不受信任的监控条目：{Reason}", reason);
                continue;
            }

            try
            {
                switch (_locker.GetLockState(path))
                {
                    case FolderLockState.Unlocked:
                        _locker.Lock(path);
                        _logger.LogWarning("已恢复被解除的锁定：{Path}", path);
                        break;
                    case FolderLockState.Unknown:
                        _logger.LogWarning("无法判定锁定状态（权限/IO 异常），已跳过：{Path}", path);
                        break;
                }
            }
            catch (FolderLockAccessException ex)
            {
                _logger.LogWarning("无法恢复锁定（缺少 WRITE_DAC，通常因服务以低权限账户运行）：{Path}；{Message}", path, ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "处理 {Path} 时出错。", path);
            }
        }
    }
}
