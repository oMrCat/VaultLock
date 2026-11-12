using System.Drawing;
using System.IO;
using System.Windows;
using Forms = System.Windows.Forms;

namespace FolderLock.App;

public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _notifyIcon;
    private readonly MainWindow _window;

    public TrayIcon(MainWindow window)
    {
        _window = window;

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("打开主界面", null, (_, _) => ShowWindow());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("退出", null, (_, _) => Exit());

        _notifyIcon = new Forms.NotifyIcon
        {
            // 用应用自身图标（ApplicationIcon 已嵌入 exe 资源），替代通用系统盾牌
            Icon = LoadAppIcon(),
            Text = "FolderLock 文件夹加锁",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _notifyIcon.DoubleClick += (_, _) => ShowWindow();
    }

    /// <summary>从 exe 提取应用图标；失败时回退系统盾牌图标。</summary>
    private static Icon LoadAppIcon()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe))
            {
                var full = Path.GetFullPath(exe);
                if (File.Exists(full))
                {
                    var icon = Icon.ExtractAssociatedIcon(full);
                    if (icon is not null)
                    {
                        return icon;
                    }
                }
            }
        }
        catch
        {
        }

        return SystemIcons.Shield;
    }

    public void ShowMinimizedNotice()
    {
        ShowBalloon("FolderLock", "程序已最小化到托盘，双击图标可重新打开。");
    }

    public void ShowBalloon(string title, string message)
    {
        _notifyIcon.BalloonTipTitle = title;
        _notifyIcon.BalloonTipText = message;
        _notifyIcon.ShowBalloonTip(3000);
    }

    public void UpdateStatus(int total, int locked)
    {
        var text = $"FolderLock：共 {total} 项，已锁定 {locked} 项";
        _notifyIcon.Text = text.Length > 63 ? text[..63] : text;
    }

    private void ShowWindow()
    {
        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
        {
            _window.WindowState = WindowState.Normal;
        }

        _window.Activate();
        _window.Topmost = true;
        _window.Topmost = false;
        _window.Focus();
    }

    private void Exit()
    {
        _window.ExitRequested = true;
        _notifyIcon.Visible = false;
        Application.Current.Shutdown();
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
    }
}
