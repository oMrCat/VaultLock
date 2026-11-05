using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using FluentWindow = Wpf.Ui.Controls.FluentWindow;

namespace FolderLock.App;

public partial class RecoveryCodeDialog : FluentWindow
{
    private const int ClipboardClearSeconds = 30;

    private readonly Action? _onSaved;
    private readonly DispatcherTimer _clipboardTimer = new() { Interval = TimeSpan.FromSeconds(ClipboardClearSeconds) };
    private readonly string _code;

    public RecoveryCodeDialog(string code, Action? onSaved = null)
    {
        InitializeComponent();
        _code = code;
        _onSaved = onSaved;
        CodeText.Text = code;
        _clipboardTimer.Tick += (_, _) =>
        {
            _clipboardTimer.Stop();
            ClearClipboardCode();
        };
        Loaded += (_, _) => CodeText.Focus();
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_code);
            CopyHint.Text = L.T("Recovery.Copied");
            CopyHint.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorSuccessBrush");
            CopyHint.Visibility = Visibility.Visible;
            ScheduleClipboardClear();
        }
        catch
        {
            CopyHint.Text = L.T("Recovery.CopyFailed");
            CopyHint.SetResourceReference(TextBlock.ForegroundProperty, "SystemFillColorCriticalBrush");
            CopyHint.Visibility = Visibility.Visible;
        }
    }

    private void Print_Click(object sender, RoutedEventArgs e)
    {
        var printDialog = new PrintDialog();
        if (printDialog.ShowDialog() != true)
        {
            return;
        }

        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            var title = new FormattedText(
                L.T("Recovery.Title"),
                CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI"),
                20,
                Brushes.Black,
                1.0);
            var body = new FormattedText(
                _code,
                CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Consolas"),
                16,
                Brushes.Black,
                1.0)
            {
                MaxTextWidth = Math.Max(200, printDialog.PrintableAreaWidth - 96),
            };
            var note = new FormattedText(
                L.T("Recovery.PrintNote"),
                CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                new Typeface("Segoe UI"),
                11,
                Brushes.Black,
                1.0)
            {
                MaxTextWidth = Math.Max(200, printDialog.PrintableAreaWidth - 96),
            };

            dc.DrawText(title, new Point(48, 48));
            dc.DrawText(body, new Point(48, 96));
            dc.DrawText(note, new Point(48, 150));
        }

        printDialog.PrintVisual(visual, L.T("Recovery.Title"));
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        _onSaved?.Invoke();
        DialogResult = true;
    }

    private void ScheduleClipboardClear()
    {
        _clipboardTimer.Stop();
        _clipboardTimer.Start();
    }

    private void ClearClipboardCode()
    {
        try
        {
            if (Clipboard.ContainsText() && Clipboard.GetText() == _code)
            {
                Clipboard.Clear();
            }
        }
        catch
        {
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        _clipboardTimer.Stop();
        ClearClipboardCode();
    }
}
