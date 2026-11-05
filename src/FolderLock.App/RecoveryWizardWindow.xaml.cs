using System.Windows;
using System.Windows.Controls;
using FolderLock.Core.Security;
using FolderLock.Core.Services;
using FluentWindow = Wpf.Ui.Controls.FluentWindow;

namespace FolderLock.App;

/// <summary>
/// “忘记密码”向导：按 <see cref="VaultRecovery"/> 给出的通道逐个尝试，
/// 明确指出“通道不存在 / 密钥错误 / 成功”，成功后允许设置新密码。
/// </summary>
public partial class RecoveryWizardWindow : FluentWindow
{
    private readonly long _folderId;
    private readonly HashSet<VaultRecoveryChannelType> _tried = new();
    private List<ChannelRow> _rows = new();
    private Secret? _workingSecret;

    public RecoveryWizardWindow(long folderId, string displayName)
    {
        InitializeComponent();
        _folderId = folderId;
        MessageText.Text = $"{L.T("Recovery.WizardDesc")}\n{L.T("Detail.Name")}：{displayName}";
        LoadChannels();
    }

    private sealed record ChannelRow(VaultRecoveryChannel Channel)
    {
        public bool Available => Channel.Available;

        public string Display =>
            Channel.Available ? Channel.Label : $"{Channel.Label}（{Channel.Reason}）";
    }

    private void LoadChannels()
    {
        try
        {
            var plan = AppServices.Folders.PlanRecovery(_folderId);
            _rows = plan.Channels.Select(channel => new ChannelRow(channel)).ToList();
            ChannelList.ItemsSource = _rows;
            ChannelList.SelectedIndex = _rows.Count == 0 ? -1 : 0;
        }
        catch (Exception ex)
        {
            ResultText.Text = ex.Message;
            ResultText.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
            VerifyButton.IsEnabled = false;
        }
    }

    private ChannelRow? SelectedRow => ChannelList.SelectedItem as ChannelRow;

    private void ChannelList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var row = SelectedRow;
        if (row is null)
        {
            ChannelReason.Text = string.Empty;
            VerifyButton.IsEnabled = false;
            return;
        }

        ChannelReason.Text = row.Channel.Reason;

        // DPAPI 通道不需要输入；恢复套件需要导入流程，当前窗口不直接验证。
        var needsSecret = row.Channel.Type is VaultRecoveryChannelType.RecoveryCode or VaultRecoveryChannelType.EmergencyPassword;
        SecretPanel.Visibility = needsSecret ? Visibility.Visible : Visibility.Collapsed;
        VerifyButton.IsEnabled = row.Available && row.Channel.Type != VaultRecoveryChannelType.RecoveryKit;
    }

    private void Verify_Click(object sender, RoutedEventArgs e)
    {
        var row = SelectedRow;
        if (row is null)
        {
            return;
        }

        var type = row.Channel.Type;
        using var secret = new Secret(
            type is VaultRecoveryChannelType.RecoveryCode or VaultRecoveryChannelType.EmergencyPassword
                ? SecretInput.Password
                : string.Empty);

        try
        {
            var result = AppServices.Folders.TryRecoveryChannel(_folderId, type, secret);
            _tried.Add(type);
            switch (result.Outcome)
            {
                case VaultRecoveryOutcome.Success:
                    _workingSecret?.Dispose();
                    _workingSecret = new Secret(secret.Span);
                    ResultText.Text = result.Message;
                    ResultText.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorSuccessBrush");
                    NewPasswordPanel.Visibility = Visibility.Visible;
                    VerifyButton.IsEnabled = false;
                    break;

                case VaultRecoveryOutcome.WrongKey:
                    ResultText.Text = result.Message;
                    ResultText.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
                    ReportExhausted();
                    break;

                default:
                    ResultText.Text = result.Message;
                    ResultText.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCautionBrush");
                    ReportExhausted();
                    break;
            }
        }
        catch (Exception ex)
        {
            ResultText.Text = ex.Message;
            ResultText.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (_workingSecret is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(NewPasswordInput.Password))
        {
            ShowError("新密码不能为空。");
            return;
        }

        if (!string.Equals(NewPasswordInput.Password, ConfirmPasswordInput.Password, StringComparison.Ordinal))
        {
            ShowError("两次输入的新密码不一致。");
            return;
        }

        try
        {
            using var next = new Secret(NewPasswordInput.Password);
            AppServices.Folders.RecoverWithNewPassword(_folderId, _workingSecret, next);
            DialogResult = true;
        }
        catch (Exception ex)
        {
            ShowError(ex.Message);
        }
    }

    private void ShowError(string message)
    {
        ResultText.Text = message;
        ResultText.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
    }

    /// <summary>所有可用通道都尝试过且未成功时，给出“密码学上不可恢复”的明确结论。</summary>
    private void ReportExhausted()
    {
        if (!_rows.Any(row => row.Available && !_tried.Contains(row.Channel.Type)))
        {
            ResultText.Text += "\n" + L.T("Recovery.Irrecoverable");
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _workingSecret?.Dispose();
        _workingSecret = null;
        base.OnClosed(e);
    }
}
