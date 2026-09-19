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
            var (verb, path) = FolderLock.App.MainWindow.ParseCommand(args);
            if (verb is not null && path is not null)
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
                    ServiceRegistration.InstallDirect();
                    return true;
                case "--uninstall-service":
                    ServiceRegistration.UninstallDirect();
                    return true;
            }
        }

        return false;
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
