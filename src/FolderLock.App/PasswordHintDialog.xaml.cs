using System.Windows;
using FolderLock.Core.Security;
using FluentWindow = Wpf.Ui.Controls.FluentWindow;

namespace FolderLock.App;

public partial class PasswordHintDialog : FluentWindow
{
    private readonly long _folderId;

    public PasswordHintDialog(long folderId, string displayName, string? currentHint)
    {
        InitializeComponent();
        _folderId = folderId;
        HintInput.Text = currentHint ?? string.Empty;
        Loaded += (_, _) => CurrentInput.Focus();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            using var current = new Secret(CurrentInput.Password);
            AppServices.Folders.SetPasswordHint(_folderId, current, HintInput.Text);
            DialogResult = true;
        }
        catch (Exception ex)
        {
            ErrorText.Text = ex.Message;
            ErrorText.Visibility = Visibility.Visible;
        }
    }
}
