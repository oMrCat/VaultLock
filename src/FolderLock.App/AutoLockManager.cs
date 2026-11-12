using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows.Threading;
using FolderLock.Core.Services;

namespace FolderLock.App;

/// <summary>自动重锁单次尝试的结果。</summary>
public enum RelockOutcome
{
    /// <summary>已成功锁定。</summary>
    Locked,

    /// <summary>可重试的临时失败（文件占用、IO 冲突等）。</summary>
    RetryableFailure,

    /// <summary>永久性失败（如未缓存密码），重试无意义。</summary>
    GaveUp,
}

public sealed class AutoLockManager : IDisposable
{
    private const int NotifyForThisSession = 0;
    private const int WmWtsSessionChange = 0x02B1;
    private const int WmHotkey = 0x0312;
    private const int WtsSessionLock = 0x7;
    private const int WtsSessionLogoff = 0x5;
    private const int HotkeyId = 0x9001;
    private const uint ModAlt = 0x0001;
    private const uint ModControl = 0x0002;
    private const uint VkL = 0x4C;

    private readonly MainWindow _window;
    private readonly DispatcherTimer _timer;
    private readonly Dictionary<long, DateTimeOffset> _unlockTimes = new();
    private readonly Dictionary<long, int> _relockFailures = new();
    private readonly RelockGate _gate = new();
    private HwndSource? _source;
    private IntPtr _handle;
    private bool _hotkeyRegistered;

    /// <summary>自动重锁连续失败的最大次数，超过后停止重试并明确告知用户。</summary>
    private const int MaxRelockAttempts = 5;

    public AutoLockManager(MainWindow window)
    {
        _window = window;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(20) };
        _timer.Tick += (_, _) => Tick();
    }

    public void Attach(IntPtr handle)
    {
        _handle = handle;
        _source = HwndSource.FromHwnd(handle);
        _source?.AddHook(WndProc);

        try
        {
            WTSRegisterSessionNotification(handle, NotifyForThisSession);
        }
        catch
        {
        }

        RegisterHotkey();
        _timer.Start();
    }

    public void RegisterHotkey()
    {
        if (_hotkeyRegistered || _handle == IntPtr.Zero || !AppSettings.Current.PanicHotkeyEnabled)
        {
            return;
        }

        _hotkeyRegistered = RegisterHotKey(_handle, HotkeyId, ModControl | ModAlt, VkL);
    }

    public void UnregisterHotkey()
    {
        if (!_hotkeyRegistered)
        {
            return;
        }

        UnregisterHotKey(_handle, HotkeyId);
        _hotkeyRegistered = false;
    }

    public void NoteUnlocked(long id)
    {
        if (AppSettings.Current.AutoRelockMinutes > 0)
        {
            _unlockTimes[id] = DateTimeOffset.UtcNow;
        }
        else
        {
            _unlockTimes.Remove(id);
        }
    }

    public void NoteLocked(long id)
    {
        _unlockTimes.Remove(id);
        _relockFailures.Remove(id);
    }

    private void Tick()
    {
        if (AppSettings.Current.AutoRelockMinutes > 0)
        {
            var window = TimeSpan.FromMinutes(AppSettings.Current.AutoRelockMinutes);
            var now = DateTimeOffset.UtcNow;
            foreach (var id in _unlockTimes.Where(pair => now - pair.Value >= window).Select(pair => pair.Key).ToList())
            {
                // single-flight：同一文件夹的重锁在上一次完成前不重复发起。
                if (!_gate.TryEnter(id))
                {
                    continue;
                }

                // 修复：此前在发起重锁前就把 id 移出 _unlockTimes，
                // 重锁失败（如文件被占用、残留容器）后本解锁周期内永远不会再重试，
                // 文件夹保持解锁状态。现在由 RelockAsync 按结果决定移除/重试。
                _ = RelockAsync(id);
            }
        }

        var idleMinutes = AppSettings.Current.AutoLockIdleMinutes;
        if (idleMinutes > 0 && GetIdleTime() >= TimeSpan.FromMinutes(idleMinutes))
        {
            _ = LockAllAsync("空闲超时");
        }
    }

    private async Task RelockAsync(long id)
    {
        try
        {
            var outcome = await _window.LockFolderSilentlyAsync(id, "临时解锁到期");
            switch (outcome)
            {
                case RelockOutcome.Locked:
                    _unlockTimes.Remove(id);
                    _relockFailures.Remove(id);
                    break;
                case RelockOutcome.GaveUp:
                    // 永久性失败（如未缓存密码）：重试无意义，等待用户手动处理。
                    _unlockTimes.Remove(id);
                    _relockFailures.Remove(id);
                    break;
                case RelockOutcome.RetryableFailure:
                    {
                        // 常见于解锁期间文件被占用/杀软扫描句柄：下个 tick 自动重试。
                        var fails = _relockFailures.GetValueOrDefault(id) + 1;
                        _relockFailures[id] = fails;
                        if (fails == 1)
                        {
                            _window.ShowRelockBalloon("自动重新锁定失败（文件夹可能仍被占用），将自动重试。");
                        }
                        else if (fails >= MaxRelockAttempts)
                        {
                            _unlockTimes.Remove(id);
                            _relockFailures.Remove(id);
                            _window.ShowRelockBalloon(
                                $"自动重新锁定已连续失败 {fails} 次，已停止重试。请关闭占用该文件夹的程序后手动锁定。");
                        }

                        break;
                    }
            }
        }
        finally
        {
            _gate.Exit(id);
        }
    }

    private async Task LockAllAsync(string reason)
    {
        // 空闲/会话锁定的全量重锁同样只允许一个在途任务。
        if (!_gate.TryEnterGlobal())
        {
            return;
        }

        try
        {
            await _window.LockAllUnlockedAsync(reason);
        }
        finally
        {
            _gate.ExitGlobal();
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WmWtsSessionChange)
        {
            var sessionEvent = wParam.ToInt32();
            if ((sessionEvent == WtsSessionLock || sessionEvent == WtsSessionLogoff) &&
                AppSettings.Current.AutoLockOnSessionLock)
            {
                _ = LockAllAsync(sessionEvent == WtsSessionLock ? "屏幕已锁定" : "用户注销");
            }
        }
        else if (msg == WmHotkey && wParam.ToInt32() == HotkeyId)
        {
            _window.PanicLock();
            handled = true;
        }

        return IntPtr.Zero;
    }

    private static TimeSpan GetIdleTime()
    {
        var info = new LastInputInfo { cbSize = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info))
        {
            return TimeSpan.Zero;
        }

        var idle = unchecked((uint)Environment.TickCount - info.dwTime);
        return TimeSpan.FromMilliseconds(idle);
    }

    public void Dispose()
    {
        _timer.Stop();
        UnregisterHotkey();

        if (_handle != IntPtr.Zero)
        {
            try
            {
                WTSUnRegisterSessionNotification(_handle);
            }
            catch
            {
            }
        }

        _source?.RemoveHook(WndProc);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSRegisterSessionNotification(IntPtr hWnd, int dwFlags);

    [DllImport("wtsapi32.dll")]
    private static extern bool WTSUnRegisterSessionNotification(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo plii);

    [DllImport("user32.dll")]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll")]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);
}
