using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows.Threading;

namespace FolderLock.App;

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
    private HwndSource? _source;
    private IntPtr _handle;
    private bool _hotkeyRegistered;

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

    public void NoteLocked(long id) => _unlockTimes.Remove(id);

    private void Tick()
    {
        if (AppSettings.Current.AutoRelockMinutes > 0)
        {
            var window = TimeSpan.FromMinutes(AppSettings.Current.AutoRelockMinutes);
            var now = DateTimeOffset.UtcNow;
            foreach (var id in _unlockTimes.Where(pair => now - pair.Value >= window).Select(pair => pair.Key).ToList())
            {
                _unlockTimes.Remove(id);
                _window.LockFolderSilently(id, "临时解锁到期");
            }
        }

        var idleMinutes = AppSettings.Current.AutoLockIdleMinutes;
        if (idleMinutes > 0 && GetIdleTime() >= TimeSpan.FromMinutes(idleMinutes))
        {
            _window.LockAllUnlocked("空闲超时");
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
                _window.LockAllUnlocked(sessionEvent == WtsSessionLock ? "屏幕已锁定" : "用户注销");
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
