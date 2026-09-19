using System.Windows;
using FluentWindow = Wpf.Ui.Controls.FluentWindow;

namespace FolderLock.App;

public partial class RecoveryCodeDialog : FluentWindow
{
    public RecoveryCodeDialog(string code)
    {
        InitializeComponent();
        CodeText.Text = code;
        Loaded += (_, _) => CodeText.Focus();
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(CodeText.Text);
            CopyHint.Visibility = Visibility.Visible;
        }
        catch
        {
            CopyHint.Text = L.T("Recovery.CopyFailed");
            CopyHint.SetResourceReference(ForegroundProperty, "SystemFillColorCriticalBrush");
            CopyHint.Visibility = Visibility.Visible;
        }
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);

        try
        {
            if (Clipboard.ContainsText() && Clipboard.GetText() == CodeText.Text)
            {
                Clipboard.Clear();
            }
        }
        catch
        {
        }
    }
}
