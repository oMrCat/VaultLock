using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;
using Microsoft.Win32;
using FluentWindow = Wpf.Ui.Controls.FluentWindow;
using SymbolRegular = Wpf.Ui.Controls.SymbolRegular;

namespace FolderLock.App;

public partial class MainWindow : FluentWindow
{
    private readonly ObservableCollection<FolderItem> _items = new();
    private readonly DispatcherTimer _watchdog;
    private readonly ICollectionView _view;
    private readonly AutoLockManager _autoLock;
    private string _filter = "All";
    private string _search = string.Empty;
    private CancellationTokenSource? _operationCts;

    public MainWindow()
    {
        InitializeComponent();
        _view = CollectionViewSource.GetDefaultView(_items);
        _view.Filter = FilterItem;
        FolderList.ItemsSource = _view;

        Closing += OnClosing;
        StartupMenuItem.IsChecked = StartupRegistration.IsEnabled();
        ApplyWindowSettings();
        UpdateThemeChecks();
        UpdateLanguageChecks();
        UpdateAutoLockChecks();
        _ = UpdateWindowsHelloAsync();
        Reload();

        _watchdog = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _watchdog.Tick += (_, _) => RunWatchdog();
        _watchdog.Start();

        _autoLock = new AutoLockManager(this);
        SourceInitialized += (_, _) =>
        {
            var handle = new WindowInteropHelper(this).Handle;
            _autoLock.Attach(handle);
        };
    }

    public void LockAllUnlocked(string reason)
    {
        Task.Run(() =>
        {
            var locked = AppServices.Folders.LockAll(AppServices.Keyring);
            if (locked.Count == 0)
            {
                return;
            }

            Dispatcher.Invoke(() =>
            {
                Reload();
                UpdateStatus($"已自动锁定 {locked.Count} 个文件夹（{reason}）。");
                Tray?.ShowBalloon("FolderLock", $"{reason}：已自动锁定 {locked.Count} 个文件夹。");
            });
        });
    }

    public void LockFolderSilently(long id, string reason)
    {
        Task.Run(() =>
        {
            try
            {
                if (!AppServices.Keyring.TryGet(id, out var secret))
                {
                    return;
                }

                AppServices.Folders.Lock(id, secret);
                AppServices.Keyring.Remove(id);

                Dispatcher.Invoke(() =>
                {
                    Reload(id);
                    UpdateStatus($"已自动重新锁定（{reason}）。");
                    Tray?.ShowBalloon("FolderLock", "临时解锁到期，已重新锁定。");
                });
            }
            catch
            {
            }
        });
    }

    public void PanicLock()
    {
        try
        {
            Clipboard.Clear();
        }
        catch
        {
        }

        WindowState = WindowState.Minimized;
        LockAllUnlocked("紧急锁定");
    }

    private void RunWatchdog()
    {
        try
        {
            if (AppServices.Folders.EnforceLocks())
            {
                Reload();
                UpdateStatus("已自动恢复被外部修改的锁定。");
            }
        }
        catch
        {
        }
    }

    public bool ExitRequested { get; set; }

    public TrayIcon? Tray { get; set; }

    private FolderItem? Selected => FolderList.SelectedItem as FolderItem;

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        SaveWindowSettings();

        if (ExitRequested)
        {
            _autoLock.Dispose();
            AppServices.Keyring.Clear();
            return;
        }

        e.Cancel = true;
        Hide();
        Tray?.ShowMinimizedNotice();
    }

    private void ApplyWindowSettings()
    {
        var settings = AppSettings.Current;

        if (settings.WindowWidth >= MinWidth)
        {
            Width = settings.WindowWidth;
        }

        if (settings.WindowHeight >= MinHeight)
        {
            Height = settings.WindowHeight;
        }

        if (!double.IsNaN(settings.WindowLeft) && !double.IsNaN(settings.WindowTop))
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = settings.WindowLeft;
            Top = settings.WindowTop;
        }

        if (settings.WindowMaximized)
        {
            WindowState = WindowState.Maximized;
        }
    }

    private void SaveWindowSettings()
    {
        var settings = AppSettings.Current;

        if (WindowState == WindowState.Maximized)
        {
            settings.WindowMaximized = true;
        }
        else
        {
            settings.WindowMaximized = false;
            settings.WindowWidth = ActualWidth;
            settings.WindowHeight = ActualHeight;
            settings.WindowLeft = Left;
            settings.WindowTop = Top;
        }

        settings.Save();
    }

    private void UpdateThemeChecks()
    {
        var theme = AppSettings.Current.Theme;
        ThemeSystemItem.IsChecked = theme == "System";
        ThemeDarkItem.IsChecked = theme == "Dark";
        ThemeLightItem.IsChecked = theme == "Light";
    }

    private void UpdateLanguageChecks()
    {
        var language = AppSettings.Current.Language;
        LangSystemItem.IsChecked = language == "System";
        LangZhItem.IsChecked = language == "中文";
        LangEnItem.IsChecked = language == "English";
    }

    private void Language_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { Tag: string language })
        {
            return;
        }

        L.SetLanguage(language);
        UpdateLanguageChecks();

        var choice = MessageBox.Show(
            this,
            L.Current == "en" ? "Restart to apply the language?" : "需要重启以应用语言，是否立即重启？",
            "FolderLock",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (choice == MessageBoxResult.Yes)
        {
            RestartApplication();
        }
    }

    private void RestartApplication()
    {
        try
        {
            if (Environment.ProcessPath is { } exe)
            {
                Process.Start(new ProcessStartInfo { FileName = exe, UseShellExecute = true });
            }
        }
        catch
        {
        }

        ExitRequested = true;
        Application.Current.Shutdown();
    }

    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem { Tag: string theme })
        {
            AppSettings.Current.Theme = theme;
            AppSettings.Current.Save();
            ThemeService.Apply(theme);
            UpdateThemeChecks();
        }
    }

    private void Reload(long? selectId = null)
    {
        _items.Clear();
        foreach (var record in AppServices.Folders.GetAll())
        {
            _items.Add(new FolderItem(record));
        }

        _view.Refresh();

        if (selectId is { } id)
        {
            var match = _items.FirstOrDefault(item => item.Id == id);
            if (match is not null)
            {
                FolderList.SelectedItem = match;
            }
        }

        UpdateStatus();
        UpdateDetail();
    }

    private void UpdateStatus(string? message = null)
    {
        var locked = _items.Count(item => item.IsLocked);
        StatusText.Text = message ?? L.T("Status.Ready");
        CountText.Text = L.Format("Status.Count", _items.Count, locked);
        Tray?.UpdateStatus(_items.Count, locked);
        UpdateNavigation();
    }

    private void UpdateNavigation()
    {
        var total = _items.Count;
        var locked = _items.Count(item => item.IsLocked);
        var encrypted = _items.Count(item => item.IsEncrypted);

        NavAllCount.Text = total.ToString();
        NavLockedCount.Text = locked.ToString();
        NavUnlockedCount.Text = (total - locked).ToString();
        NavEncryptedCount.Text = encrypted.ToString();

        var visible = _items.Count(FilterItem);
        PageTitle.Text = _filter switch
        {
            "Locked" => L.T("Page.Locked"),
            "Unlocked" => L.T("Page.Unlocked"),
            "Encrypted" => L.T("Page.Encrypted"),
            _ => L.T("Page.All"),
        };
        PageSubtitle.Text = L.Format("Page.Count", visible);

        var empty = visible == 0;
        EmptyState.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        FolderList.Visibility = empty ? Visibility.Collapsed : Visibility.Visible;
    }

    private bool FilterItem(object obj)
    {
        if (obj is not FolderItem item)
        {
            return false;
        }

        var navMatch = _filter switch
        {
            "Locked" => item.IsLocked,
            "Unlocked" => !item.IsLocked,
            "Encrypted" => item.IsEncrypted,
            _ => true,
        };

        if (!navMatch)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(_search))
        {
            return true;
        }

        var query = _search.Trim();
        return item.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
               || item.Path.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateDetail()
    {
        var item = Selected;
        if (item is null)
        {
            DetailPanel.Visibility = Visibility.Collapsed;
            return;
        }

        DetailPanel.Visibility = Visibility.Visible;
        DetailName.Text = item.DisplayName;
        DetailPath.Text = item.Path;
        DetailStatus.Text = item.StatusText;
        DetailMode.Text = item.ModeText;
        DetailLast.Text = item.LastLockedText;
        DetailIcon.Symbol = item.IsLocked
            ? SymbolRegular.LockClosed24
            : SymbolRegular.LockOpen24;
    }

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string tag })
        {
            _filter = tag;
            _view.Refresh();
            UpdateNavigation();
            UpdateDetail();
        }
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _search = SearchBox.Text ?? string.Empty;
        _view.Refresh();
        UpdateNavigation();
    }

    private void FolderList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateDetail();
    }

    private void More_Click(object sender, RoutedEventArgs e)
    {
        if (MoreButton.ContextMenu is { } menu)
        {
            menu.PlacementTarget = MoreButton;
            menu.IsOpen = true;
        }
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择要加锁的文件夹",
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var passwordDialog = new PasswordDialog(
            L.T("Dialog.SetPassword"),
            "为该文件夹设置访问密码：",
            requireConfirmation: true,
            showEncryptionOption: true)
        {
            Owner = this,
        };

        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            using var secret = passwordDialog.GetSecret();
            var record = AppServices.Folders.Add(
                dialog.FolderName,
                secret,
                passwordDialog.UseEncryption,
                out var recoveryCode);

            if (recoveryCode is not null)
            {
                ShowRecoveryCode(recoveryCode);
            }

            Reload(record.Id);
            UpdateStatus("已添加文件夹。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void ShowRecoveryCode(string code)
    {
        new RecoveryCodeDialog(code) { Owner = this }.ShowDialog();
    }

    private async void Lock_Click(object sender, RoutedEventArgs e)
    {
        var item = Selected;
        if (item is null)
        {
            WarnSelectFolder();
            return;
        }

        if (item.IsLocked)
        {
            ShowInfo("该文件夹已处于锁定状态。");
            return;
        }

        var dialog = new PasswordDialog(L.T("Dialog.Lock"), $"输入“{item.DisplayName}”的密码以锁定：") { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        using var secret = dialog.GetSecret();

        if (item.IsEncrypted)
        {
            await RunVaultOperationAsync(
                "正在加密",
                (progress, token) => AppServices.Folders.LockAsync(item.Id, secret, progress, token));
            Reload(item.Id);
            ReportLockResult(item);
            return;
        }

        try
        {
            AppServices.Folders.Lock(item.Id, secret);
            Reload(item.Id);
            ReportLockResult(item);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void RememberSecret(long id, Secret secret)
    {
        if (AppSettings.Current.CachePasswords)
        {
            AppServices.Keyring.Store(id, secret);
        }

        _autoLock.NoteUnlocked(id);
    }

    private void ReportLockResult(FolderItem item)
    {
        AppServices.Keyring.Remove(item.Id);
        _autoLock.NoteLocked(item.Id);

        if (AppServices.Folders.LastTraceClean is { } clean)
        {
            UpdateStatus(
                $"已加密并清理痕迹：快捷方式 {clean.ShortcutsRemoved}、注册表 {clean.RegistryValuesRemoved}、缓存 {clean.CacheFilesRemoved}。");
        }
        else
        {
            UpdateStatus($"已锁定：{item.DisplayName}");
        }
    }

    private async void Unlock_Click(object sender, RoutedEventArgs e)
    {
        var item = Selected;
        if (item is null)
        {
            WarnSelectFolder();
            return;
        }

        if (!item.IsLocked)
        {
            ShowInfo("该文件夹当前未锁定。");
            return;
        }

        if (await TryUnlockAsync(item))
        {
            Reload(item.Id);
            UpdateStatus($"已解锁：{item.DisplayName}");
            TryOpen(item);
        }
    }

    private async Task<bool> TryUnlockAsync(FolderItem item)
    {
        var prompt = item.IsEncrypted
            ? $"输入“{item.DisplayName}”的密码或恢复码以解锁："
            : $"输入“{item.DisplayName}”的密码以解锁：";
        var dialog = new PasswordDialog(L.T("Dialog.Unlock"), prompt) { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return false;
        }

        using var secret = dialog.GetSecret();

#if !FOLDERLOCK_NO_HELLO
        if (AppSettings.Current.WindowsHello && await WindowsHello.IsAvailableAsync())
        {
            var message = L.Current == "en" ? "Verify to unlock" : "请验证以解锁";
            if (!await WindowsHello.VerifyAsync(message))
            {
                UpdateStatus(L.Current == "en" ? "Windows Hello verification failed." : "Windows Hello 验证未通过。");
                return false;
            }
        }
#endif

        if (item.IsEncrypted)
        {
            var success = false;
            await RunVaultOperationAsync("正在解密", async (progress, token) =>
            {
                await AppServices.Folders.UnlockAsync(item.Id, secret, progress, token);
                success = true;
            });

            if (success)
            {
                RememberSecret(item.Id, secret);
            }

            return success;
        }

        try
        {
            AppServices.Folders.Unlock(item.Id, secret);
            RememberSecret(item.Id, secret);
            return true;
        }
        catch (Exception ex)
        {
            ShowError(ex);
            return false;
        }
    }

    private async Task RunVaultOperationAsync(
        string title,
        Func<IProgress<VaultProgress>, CancellationToken, Task> operation)
    {
        _operationCts = new CancellationTokenSource();
        ProgressOverlay.Visibility = Visibility.Visible;
        CancelButton.IsEnabled = true;
        ProgressText.Text = $"{title}…";

        var progress = new Progress<VaultProgress>(value =>
        {
            ProgressText.Text = $"{title}… {value.Percent:0}%";
        });

        try
        {
            await operation(progress, _operationCts.Token);
        }
        catch (OperationCanceledException)
        {
            UpdateStatus("操作已取消。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            ProgressOverlay.Visibility = Visibility.Collapsed;
            _operationCts.Dispose();
            _operationCts = null;
        }
    }

    private void CancelOperation_Click(object sender, RoutedEventArgs e)
    {
        _operationCts?.Cancel();
        CancelButton.IsEnabled = false;
        ProgressText.Text = "正在取消…";
    }

    private void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        var item = Selected;
        if (item is null)
        {
            WarnSelectFolder();
            return;
        }

        var dialog = new ChangePasswordDialog(L.T("Dialog.ChangePassword")) { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            using var current = dialog.GetCurrentSecret();
            using var next = dialog.GetNewSecret();
            AppServices.Folders.ChangePassword(item.Id, current, next);
            UpdateStatus("密码已更新。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void ViewRecovery_Click(object sender, RoutedEventArgs e)
    {
        var item = Selected;
        if (item is null)
        {
            WarnSelectFolder();
            return;
        }

        if (!item.IsEncrypted)
        {
            ShowInfo("该文件夹未使用加密，无需恢复码。");
            return;
        }

        try
        {
            var code = AppServices.Folders.GetRecoveryCode(item.Id);
            if (code is null)
            {
                ShowInfo("无法读取恢复码（可能由其他 Windows 账户创建）。");
                return;
            }

            ShowRecoveryCode(code);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        var item = Selected;
        if (item is null)
        {
            WarnSelectFolder();
            return;
        }

        var dialog = new PasswordDialog(L.T("Dialog.Remove"), $"输入“{item.DisplayName}”的密码以从列表移除（不会删除文件）：") { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            using var secret = dialog.GetSecret();
            AppServices.Folders.Remove(item.Id, secret);
            Reload();
            UpdateStatus("已移除。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private async void Open_Click(object sender, RoutedEventArgs e)
    {
        var item = Selected;
        if (item is null)
        {
            WarnSelectFolder();
            return;
        }

        if (item.IsLocked)
        {
            if (await TryUnlockAsync(item))
            {
                Reload(item.Id);
                TryOpen(item);
            }

            return;
        }

        TryOpen(item);
    }

    private void FolderList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        Open_Click(sender, e);
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            AppServices.Folders.SyncLockStates();
            Reload();
            UpdateStatus("已刷新。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void FolderList_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void FolderList_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] paths)
        {
            return;
        }

        var folders = paths
            .Where(path => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (folders.Count == 0)
        {
            return;
        }

        var passwordDialog = new PasswordDialog(
            L.T("Dialog.SetPassword"),
            $"为拖入的 {folders.Count} 个文件夹设置统一密码：",
            requireConfirmation: true,
            showEncryptionOption: true)
        {
            Owner = this,
        };

        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        using var sharedSecret = passwordDialog.GetSecret();
        var added = 0;
        var failures = new List<string>();
        var recoveryCodes = new List<string>();
        foreach (var folder in folders)
        {
            try
            {
                AppServices.Folders.Add(
                    folder,
                    sharedSecret,
                    passwordDialog.UseEncryption,
                    out var recoveryCode);

                if (recoveryCode is not null)
                {
                    recoveryCodes.Add(recoveryCode);
                }

                added++;
            }
            catch (Exception ex)
            {
                failures.Add($"{folder}：{ex.Message}");
            }
        }

        foreach (var code in recoveryCodes)
        {
            ShowRecoveryCode(code);
        }

        Reload();
        if (failures.Count > 0)
        {
            MessageBox.Show(
                this,
                $"已添加 {added} 个文件夹，{failures.Count} 个失败：\n\n{string.Join("\n", failures)}",
                "FolderLock",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        else
        {
            UpdateStatus($"已添加 {added} 个文件夹。");
        }
    }

    private void TryOpen(FolderItem item)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = item.Path,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    public void HandleStartupArgs(string[] args)
    {
        var (verb, path) = ParseCommand(args);
        if (verb is not null && path is not null)
        {
            HandleExternalCommand(verb, path);
        }
    }

    public static (string? Verb, string? Path) ParseCommand(string[] args)
    {
        if (args.Length == 0)
        {
            return (null, null);
        }

        if (args.Length == 1)
        {
            return ("add", args[0]);
        }

        var first = args[0];
        if (first.StartsWith("--", StringComparison.Ordinal))
        {
            return (first[2..].ToLowerInvariant(), args[1]);
        }

        return ("add", first);
    }

    public void HandleExternalCommand(string verb, string path)
    {
        Show();
        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
        Reload();

        try
        {
            switch (verb)
            {
                case "add":
                    ExternalAdd(path);
                    break;
                case "lock":
                    ExternalLock(path);
                    break;
                case "unlock":
                    ExternalUnlock(path);
                    break;
            }
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void ExternalAdd(string path)
    {
        var normalized = NormalizeExisting(path);
        if (normalized is null)
        {
            return;
        }

        if (AppServices.Folders.GetByPath(normalized) is not null)
        {
            ShowInfo("该文件夹已在列表中。");
            return;
        }

        var dialog = new PasswordDialog(
            L.T("Dialog.SetPassword"),
            $"为“{Path.GetFileName(normalized)}”设置访问密码：",
            requireConfirmation: true,
            showEncryptionOption: true)
        {
            Owner = this,
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        using var secret = dialog.GetSecret();
        var record = AppServices.Folders.Add(
            normalized,
            secret,
            dialog.UseEncryption,
            out var recoveryCode);

        if (recoveryCode is not null)
        {
            ShowRecoveryCode(recoveryCode);
        }

        Reload(record.Id);
        UpdateStatus("已添加文件夹。");
    }

    private void ExternalLock(string path)
    {
        var normalized = NormalizeExisting(path);
        if (normalized is null)
        {
            return;
        }

        var record = AppServices.Folders.GetByPath(normalized);
        if (record is null)
        {
            var create = new PasswordDialog(
                L.T("Dialog.SetPassword"),
                $"为“{Path.GetFileName(normalized)}”设置访问密码：",
                requireConfirmation: true,
                showEncryptionOption: true)
            {
                Owner = this,
            };

            if (create.ShowDialog() != true)
            {
                return;
            }

            using var createdSecret = create.GetSecret();
            record = AppServices.Folders.Add(
                normalized,
                createdSecret,
                create.UseEncryption,
                out var recoveryCode);

            if (recoveryCode is not null)
            {
                ShowRecoveryCode(recoveryCode);
            }

            AppServices.Folders.Lock(record.Id, createdSecret);
            Reload(record.Id);
            UpdateStatus("已锁定。");
            return;
        }

        if (record.IsLocked)
        {
            ShowInfo("该文件夹已处于锁定状态。");
            return;
        }

        var dialog = new PasswordDialog(L.T("Dialog.Lock"), $"输入“{record.DisplayName}”的密码以锁定：") { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        using var secret = dialog.GetSecret();
        AppServices.Folders.Lock(record.Id, secret);
        Reload(record.Id);
        UpdateStatus("已锁定。");
    }

    private void ExternalUnlock(string path)
    {
        var normalized = NormalizeExisting(path);
        if (normalized is null)
        {
            return;
        }

        var record = AppServices.Folders.GetByPath(normalized);
        if (record is null)
        {
            ShowInfo("该文件夹不在列表中。");
            return;
        }

        if (!record.IsLocked)
        {
            ShowInfo("该文件夹当前未锁定。");
            return;
        }

        var dialog = new PasswordDialog(L.T("Dialog.Unlock"), $"输入“{record.DisplayName}”的密码以解锁：") { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        using var secret = dialog.GetSecret();
        AppServices.Folders.Unlock(record.Id, secret);
        Reload(record.Id);
        UpdateStatus("已解锁。");
    }

    private string? NormalizeExisting(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (!Directory.Exists(full))
        {
            ShowInfo($"文件夹不存在：{full}");
            return null;
        }

        return full;
    }

    private void InstallShell_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ShellIntegration.Install();
            ShowInfo("已注册右键菜单。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void UninstallShell_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ShellIntegration.Uninstall();
            ShowInfo("已移除右键菜单。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void ToggleStartup_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (StartupMenuItem.IsChecked)
            {
                StartupRegistration.Enable();
                ShowInfo("已设置开机自启（启动后最小化到托盘）。");
            }
            else
            {
                StartupRegistration.Disable();
                ShowInfo("已取消开机自启。");
            }
        }
        catch (Exception ex)
        {
            StartupMenuItem.IsChecked = StartupRegistration.IsEnabled();
            ShowError(ex);
        }
    }

    private void UpdateAutoLockChecks()
    {
        var settings = AppSettings.Current;
        AutoLockSessionItem.IsChecked = settings.AutoLockOnSessionLock;
        AutoLockIdleItem.IsChecked = settings.AutoLockIdleMinutes > 0;
        AutoRelockItem.IsChecked = settings.AutoRelockMinutes > 0;
        PanicHotkeyItem.IsChecked = settings.PanicHotkeyEnabled;
    }

    private void AutoLockSession_Click(object sender, RoutedEventArgs e)
    {
        AppSettings.Current.AutoLockOnSessionLock = AutoLockSessionItem.IsChecked;
        AppSettings.Current.Save();
    }

    private void AutoLockIdle_Click(object sender, RoutedEventArgs e)
    {
        AppSettings.Current.AutoLockIdleMinutes = AutoLockIdleItem.IsChecked ? 15 : 0;
        AppSettings.Current.Save();
    }

    private void AutoRelock_Click(object sender, RoutedEventArgs e)
    {
        AppSettings.Current.AutoRelockMinutes = AutoRelockItem.IsChecked ? 10 : 0;
        AppSettings.Current.Save();
    }

    private void PanicHotkey_Click(object sender, RoutedEventArgs e)
    {
        AppSettings.Current.PanicHotkeyEnabled = PanicHotkeyItem.IsChecked;
        AppSettings.Current.Save();

        if (PanicHotkeyItem.IsChecked)
        {
            _autoLock.RegisterHotkey();
        }
        else
        {
            _autoLock.UnregisterHotkey();
        }
    }

    private async Task UpdateWindowsHelloAsync()
    {
#if FOLDERLOCK_NO_HELLO
        WindowsHelloItem.Visibility = Visibility.Collapsed;
        AppSettings.Current.WindowsHello = false;
        await Task.CompletedTask;
#else
        var available = await WindowsHello.IsAvailableAsync();
        WindowsHelloItem.IsEnabled = available;

        if (!available && AppSettings.Current.WindowsHello)
        {
            AppSettings.Current.WindowsHello = false;
            AppSettings.Current.Save();
        }

        WindowsHelloItem.IsChecked = available && AppSettings.Current.WindowsHello;
#endif
    }

    private async void WindowsHello_Click(object sender, RoutedEventArgs e)
    {
#if FOLDERLOCK_NO_HELLO
        await Task.CompletedTask;
#else
        if (WindowsHelloItem.IsChecked && !await WindowsHello.IsAvailableAsync())
        {
            WindowsHelloItem.IsChecked = false;
            ShowInfo(L.Current == "en"
                ? "Windows Hello is not available on this device."
                : "此设备不支持 Windows Hello。");
            return;
        }

        AppSettings.Current.WindowsHello = WindowsHelloItem.IsChecked;
        AppSettings.Current.Save();
#endif
    }

    private void InstallService_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ServiceRegistration.InstallElevated();
            ShowInfo("守护服务安装命令已执行。\n可在“服务”管理器中查看 FolderLockGuard。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void UninstallService_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ServiceRegistration.UninstallElevated();
            ShowInfo("守护服务卸载命令已执行。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private async void CheckUpdate_Click(object sender, RoutedEventArgs e)
    {
        var url = AppSettings.Current.UpdateUrl;
        if (string.IsNullOrWhiteSpace(url))
        {
            ShowInfo(L.Current == "en"
                ? "No update source configured. Set UpdateUrl in settings.json."
                : "未配置更新源。请在 settings.json 中设置 UpdateUrl。");
            return;
        }

        try
        {
            var current = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";
            var manifest = await FolderLock.Core.Update.Updater.CheckAsync(url, current);

            if (manifest is null)
            {
                ShowInfo(L.Current == "en" ? "You are on the latest version." : "已是最新版本。");
                return;
            }

            var choice = MessageBox.Show(
                this,
                $"{(L.Current == "en" ? "New version" : "发现新版本")} {manifest.Version}\n{manifest.Notes}",
                "FolderLock",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (choice != MessageBoxResult.Yes)
            {
                return;
            }

            var target = Path.Combine(Path.GetTempPath(), "FolderLock.App.new.exe");
            await FolderLock.Core.Update.Updater.DownloadAsync(manifest, target);
            ApplyUpdate(target);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void ApplyUpdate(string newExecutable)
    {
        var current = Environment.ProcessPath;
        if (string.IsNullOrEmpty(current))
        {
            return;
        }

        var script = Path.Combine(Path.GetTempPath(), $"folderlock-update-{Guid.NewGuid():N}.cmd");
        var content =
            "@echo off\r\n" +
            "timeout /t 1 /nobreak >nul\r\n" +
            $"copy /y \"{newExecutable}\" \"{current}\" >nul\r\n" +
            $"start \"\" \"{current}\"\r\n" +
            "del \"%~f0\"\r\n";

        File.WriteAllText(script, content);

        Process.Start(new ProcessStartInfo
        {
            FileName = script,
            UseShellExecute = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        });

        ExitRequested = true;
        Application.Current.Shutdown();
    }

    private void ViewLogs_Click(object sender, RoutedEventArgs e)
    {
        new LogsWindow { Owner = this }.ShowDialog();
    }

    private void VaultTools_Click(object sender, RoutedEventArgs e)
    {
        var item = Selected;
        if (item is null)
        {
            WarnSelectFolder();
            return;
        }

        if (!item.IsEncrypted)
        {
            ShowInfo("该文件夹未使用加密，无需校验容器。");
            return;
        }

        var dialog = new PasswordDialog(L.T("Dialog.Verify"), $"输入“{item.DisplayName}”的密码或恢复码：") { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        using var secret = dialog.GetSecret();
        try
        {
            var info = AppServices.Folders.InspectVault(item.Id);
            if (AppServices.Folders.VerifyVault(item.Id, secret))
            {
                ShowInfo(
                    $"容器完好。\n版本：{info.Version}\nKDF 迭代：{info.Iterations}\n含恢复码：{(info.HasRecovery ? "是" : "否")}\n大小：{info.Size / 1024.0 / 1024.0:0.0} MB");
                return;
            }

            var choice = MessageBox.Show(
                this,
                "容器校验失败，可能已损坏。是否尝试救援可恢复的内容？",
                "FolderLock",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (choice != MessageBoxResult.Yes)
            {
                return;
            }

            var folderDialog = new OpenFolderDialog { Title = "选择救援输出位置" };
            if (folderDialog.ShowDialog(this) != true)
            {
                return;
            }

            var output = Path.Combine(folderDialog.FolderName, item.DisplayName + "-救援");
            var result = AppServices.Folders.SalvageVault(item.Id, secret, output);

            ShowInfo(result.Success
                ? $"救援完成，内容已还原到：\n{output}"
                : $"救援可能不完整：{result.Error}\n已尝试输出到：\n{output}");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void ExportKit_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new PasswordDialog(L.T("Dialog.ExportKit"), "为恢复套件设置保护口令：", requireConfirmation: true)
        {
            Owner = this,
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        using var secret = dialog.GetSecret();

        var save = new SaveFileDialog
        {
            Title = "导出恢复套件",
            FileName = $"FolderLock-Kit-{DateTime.Now:yyyyMMdd-HHmm}.flkit",
            Filter = "FolderLock 恢复套件 (*.flkit)|*.flkit|所有文件 (*.*)|*.*",
        };

        if (save.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var count = AppServices.Folders.ExportKit(save.FileName, secret);
            ShowInfo($"已导出 {count} 项到：\n{save.FileName}");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void ImportKit_Click(object sender, RoutedEventArgs e)
    {
        var open = new OpenFileDialog
        {
            Title = "导入恢复套件",
            Filter = "FolderLock 恢复套件 (*.flkit)|*.flkit|所有文件 (*.*)|*.*",
        };

        if (open.ShowDialog(this) != true)
        {
            return;
        }

        var dialog = new PasswordDialog(L.T("Dialog.ImportKit"), "输入恢复套件的保护口令：") { Owner = this };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        using var secret = dialog.GetSecret();

        try
        {
            var count = AppServices.Folders.ImportKit(open.FileName, secret);
            Reload();
            ShowInfo($"已导入 {count} 项。");
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void OpenDataDir_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var directory = Path.GetDirectoryName(FolderStore.GetDefaultDatabasePath())!;
            Directory.CreateDirectory(directory);
            Process.Start(new ProcessStartInfo { FileName = directory, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private void SafetyInfo_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            this,
            "FolderLock 提供两种加锁方式：\n\n" +
            "【权限锁】基于 NTFS 权限，加解锁极快。\n" +
            "• 可阻止本机其他标准用户访问。\n" +
            "• 不防管理员、系统账户或安全模式绕过。\n" +
            "• 忘记密码时，可在文件夹属性“安全”页手动恢复权限。\n\n" +
            "【AES 加密】使用 AES-256-GCM 将文件夹加密为 .flvault 容器。\n" +
            "• 即使被拷贝走或离线访问，无密码也无法解密。\n" +
            "• 忘记密码时可用恢复码解锁，请务必另行抄录备份。\n" +
            "• 加锁时会用随机数据覆写源文件后再删除，并清理最近使用记录、\n" +
            "  跳转列表、常见对话框 MRU 及缩略图缓存。\n" +
            "• 注意：SSD 的 TRIM/磨损均衡、页面文件、系统搜索索引等仍可能\n" +
            "  残留数据副本，本工具无法彻底清除，请配合全盘加密使用。\n" +
            "• 加解锁需要时间，大文件夹请耐心等待。",
            "安全说明",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void ShowInfo(string message)
    {
        MessageBox.Show(this, message, "FolderLock", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void WarnSelectFolder()
    {
        MessageBox.Show(this, "请先在列表中选择一个文件夹。", "FolderLock", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ShowError(Exception ex)
    {
        var message = ex is FolderLockException ? ex.Message : $"操作失败：{ex.Message}";
        MessageBox.Show(this, message, "FolderLock", MessageBoxButton.OK, MessageBoxImage.Warning);
    }
}
