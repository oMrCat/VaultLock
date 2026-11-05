using System.Windows;
using FolderLock.Core.Security;
using FluentWindow = Wpf.Ui.Controls.FluentWindow;

namespace FolderLock.App;

public partial class PasswordDialog : FluentWindow
{
    private readonly bool _requireConfirmation;

    public PasswordDialog(
        string title,
        string message,
        bool requireConfirmation = false,
        bool showEncryptionOption = false,
        bool showForgotPassword = false,
        string? hint = null)
    {
        InitializeComponent();
        Title = title;
        DialogTitleBar.Title = title;
        MessageText.Text = message;
        _requireConfirmation = requireConfirmation;
        ConfirmPanel.Visibility = requireConfirmation ? Visibility.Visible : Visibility.Collapsed;
        EncryptionCheck.Visibility = showEncryptionOption ? Visibility.Visible : Visibility.Collapsed;
        ForgotPasswordButton.Visibility = showForgotPassword ? Visibility.Visible : Visibility.Collapsed;
        if (!string.IsNullOrWhiteSpace(hint))
        {
            HintText.Text = L.T("Hint.Visible") + hint;
            HintText.Visibility = Visibility.Visible;
        }

        Loaded += (_, _) => PasswordInput.Focus();
    }

    /// <summary>用户点击“忘记密码？”时为 true；调用方应转入恢复向导。</summary>
    public bool ForgotPasswordRequested { get; private set; }

    public string Password => PasswordInput.Password;

    public bool UseEncryption => EncryptionCheck.IsChecked == true;

    public Secret GetSecret()
    {
        var secret = new Secret(PasswordInput.Password);
        PasswordInput.Clear();
        ConfirmInput.Clear();
        return secret;
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        using var generated = Secret.Random(18);
        var value = generated.Span.ToString();
        PasswordInput.Password = value;
        ConfirmInput.Password = value;
        UpdateStrength();
    }

    private void PasswordInput_PasswordChanged(object sender, RoutedEventArgs e) => UpdateStrength();

    private void UpdateStrength()
    {
        var level = PasswordStrength.Evaluate(PasswordInput.Password);
        StrengthBar.Value = (int)level;
        StrengthText.Text = L.T("Strength." + (int)level);
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(Password))
        {
            ShowError("密码不能为空。");
            return;
        }

        if (_requireConfirmation && !string.Equals(Password, ConfirmInput.Password, StringComparison.Ordinal))
        {
            ShowError("两次输入的密码不一致。");
            return;
        }

        DialogResult = true;
    }

    private void ForgotPassword_Click(object sender, RoutedEventArgs e)
    {
        ForgotPasswordRequested = true;
        DialogResult = true;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
