using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace FolderLock.App;

public static class ThemeService
{
    public static void Apply(string theme)
    {
        var applicationTheme = theme switch
        {
            "Dark" => ApplicationTheme.Dark,
            "Light" => ApplicationTheme.Light,
            _ => ApplicationThemeManager.GetSystemTheme() == SystemTheme.Dark
                ? ApplicationTheme.Dark
                : ApplicationTheme.Light,
        };

        ApplicationThemeManager.Apply(applicationTheme, WindowBackdropType.Mica, updateAccent: true);
    }
}
