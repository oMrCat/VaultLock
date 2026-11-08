using System.Windows;
using System.Windows.Threading;

namespace FolderLock.App;

public partial class App : Application
{
    private TrayIcon? _tray;
    private SingleInstance? _instance;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        if (RunHeadlessShellCommand(e.Args))
        {
            Shutdown();
            return;
        }

        ThemeService.Apply(AppSettings.Current.Theme);
        var integrityOk = SelfIntegrity.Ensure();

        var args = e.Args
            .Where(a => !string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var startHidden = args.Length != e.Args.Length;

        _instance = new SingleInstance();
        if (!_instance.IsFirstInstance)
        {
            foreach (var (verb, path) in FolderLock.App.MainWindow.ParseCommands(args))
            {
                SingleInstance.Forward(verb, path);
            }

            Shutdown();
            return;
        }

        var window = new MainWindow();
        _tray = new TrayIcon(window);
        window.Tray = _tray;
        _instance.CommandReceived += line => Dispatcher.Invoke(() => DispatchCommand(window, line));
        _instance.StartServer();

        window.Show();
        if (startHidden)
        {
            window.Hide();
        }

        if (!integrityOk)
        {
            _tray.ShowBalloon(
                "FolderLock",
                L.Current == "en"
                    ? "Warning: the program file appears to have been modified."
                    : "警告：程序文件似乎已被修改，可能不安全。");
        }

        if (args.Length > 0)
        {
            Dispatcher.BeginInvoke(() => window.HandleStartupArgs(args));
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        _instance?.Dispose();
        base.OnExit(e);
    }

    /// <summary>
    /// 释放单实例互斥体，供“语言切换后重启”在启动新进程前调用，
    /// 避免新进程误判已有实例而直接退出。
    /// </summary>
    public static void ReleaseSingleInstance()
    {
        if (Current is App app)
        {
            app._instance?.Dispose();
            app._instance = null;
        }
    }

    private static bool RunHeadlessShellCommand(string[] args)
    {
        foreach (var arg in args)
        {
            switch (arg)
            {
                case "--install-shell":
                    ShellIntegration.Install();
                    return true;
                case "--uninstall-shell":
                    ShellIntegration.Uninstall();
                    return true;
                case "--install-service":
                    TryServiceCommand(() => ServiceRegistration.InstallDirect());
                    return true;
                case "--uninstall-service":
                    TryServiceCommand(() => ServiceRegistration.UninstallDirect());
                    return true;
            }
        }

        return false;
    }

    /// <summary>CLI 服务命令：失败（如 UAC 被取消、未找到服务 exe）时给出明确退出码而不是静默/崩溃。</summary>
    private static void TryServiceCommand(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            Environment.ExitCode = 1;
        }
    }

    private static void DispatchCommand(MainWindow window, string payload)
    {
        var separator = payload.IndexOf('|');
        if (separator <= 0)
        {
            return;
        }

        var verb = payload[..separator];
        var path = payload[(separator + 1)..];
        window.HandleExternalCommand(verb, path);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            $"发生未处理的错误：{e.Exception.Message}",
            "FolderLock",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }
}
