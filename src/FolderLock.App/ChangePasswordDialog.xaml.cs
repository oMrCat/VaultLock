using System.Windows;
using FolderLock.Core.Security;
using FluentWindow = Wpf.Ui.Controls.FluentWindow;

namespace FolderLock.App;

public partial class ChangePasswordDialog : FluentWindow
{
    public ChangePasswordDialog(string message)
    {
        InitializeComponent();
        MessageText.Text = message;
        Loaded += (_, _) => CurrentInput.Focus();
    }

    public string CurrentPassword => CurrentInput.Password;

    public string NewPassword => NewInput.Password;

    public Secret GetCurrentSecret()
    {
        var secret = new Secret(CurrentInput.Password);
        CurrentInput.Clear();
        return secret;
    }

    public Secret GetNewSecret()
    {
        var secret = new Secret(NewInput.Password);
        NewInput.Clear();
        ConfirmInput.Clear();
        return secret;
    }

    private void NewInput_PasswordChanged(object sender, RoutedEventArgs e)
    {
        var level = PasswordStrength.Evaluate(NewInput.Password);
        StrengthBar.Value = (int)level;
        StrengthText.Text = L.T("Strength." + (int)level);
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(CurrentPassword))
        {
            ShowError("请输入当前密码。");
            return;
        }

        if (string.IsNullOrEmpty(NewPassword))
        {
            ShowError("新密码不能为空。");
            return;
        }

        if (!string.Equals(NewPassword, ConfirmInput.Password, StringComparison.Ordinal))
        {
            ShowError("两次输入的新密码不一致。");
            return;
        }

        DialogResult = true;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
