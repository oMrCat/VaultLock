using System.Globalization;
using System.Windows.Markup;

namespace FolderLock.App;

public static class L
{
    private static readonly Dictionary<string, (string Zh, string En)> Map = new()
    {
        ["App.Title"] = ("FolderLock 文件夹加锁", "FolderLock"),
        ["Nav.Section"] = ("文件夹", "Folders"),
        ["Nav.All"] = ("全部", "All"),
        ["Nav.Locked"] = ("已锁定", "Locked"),
        ["Nav.Unlocked"] = ("已解锁", "Unlocked"),
        ["Nav.Encrypted"] = ("AES 加密", "AES encrypted"),
        ["Btn.AddFolder"] = ("添加文件夹", "Add folder"),
        ["Btn.Lock"] = ("加锁", "Lock"),
        ["Btn.Unlock"] = ("解锁", "Unlock"),
        ["Btn.Refresh"] = ("刷新", "Refresh"),
        ["Search.Placeholder"] = ("搜索名称或路径", "Search name or path"),
        ["Banner"] = ("提示：选中文件夹后点击“加锁/解锁”，可将文件夹直接拖入列表。对敏感数据请使用 AES 加密。",
                      "Tip: select a folder and click Lock/Unlock, or drag folders into the list. Use AES encryption for sensitive data."),
        ["Status.Locked"] = ("已锁定", "Locked"),
        ["Status.Unlocked"] = ("已解锁", "Unlocked"),
        ["Mode.Acl"] = ("权限锁", "ACL lock"),
        ["Mode.Aes"] = ("AES 加密", "AES"),
        ["Page.All"] = ("全部文件夹", "All folders"),
        ["Page.Locked"] = ("已锁定", "Locked"),
        ["Page.Unlocked"] = ("已解锁", "Unlocked"),
        ["Page.Encrypted"] = ("AES 加密", "AES encrypted"),
        ["Page.Count"] = ("{0} 个项目", "{0} items"),
        ["Empty.Title"] = ("还没有文件夹", "No folders yet"),
        ["Empty.Hint"] = ("点击左下角“添加文件夹”，或把文件夹拖到这里", "Click Add folder, or drag folders here"),
        ["Column.Name"] = ("名称", "Name"),
        ["Detail.Path"] = ("路径", "Path"),
        ["Detail.Mode"] = ("方式", "Mode"),
        ["Detail.Last"] = ("上次锁定", "Last locked"),
        ["Detail.Open"] = ("打开文件夹", "Open folder"),
        ["Detail.ChangePassword"] = ("修改密码", "Change password"),
        ["Detail.ViewRecovery"] = ("查看恢复码", "View recovery code"),
        ["Detail.Remove"] = ("移除", "Remove"),
        ["Status.Ready"] = ("就绪", "Ready"),
        ["Status.Count"] = ("共 {0} 项，已锁定 {1} 项", "{0} total, {1} locked"),
        ["Menu.Tools"] = ("工具", "Tools"),
        ["Menu.Help"] = ("帮助", "Help"),
        ["Menu.RegisterShell"] = ("注册右键菜单", "Register context menu"),
        ["Menu.UnregisterShell"] = ("移除右键菜单", "Remove context menu"),
        ["Menu.Startup"] = ("开机自启（托盘）", "Start with Windows (tray)"),
        ["Menu.AutoLock"] = ("自动锁定", "Auto-lock"),
        ["Menu.AutoLockSession"] = ("锁屏/注销时自动锁定", "Lock on sign-out/screen lock"),
        ["Menu.AutoLockIdle"] = ("空闲 15 分钟自动锁定", "Lock when idle for 15 min"),
        ["Menu.AutoRelock"] = ("解锁后 10 分钟自动重锁", "Re-lock 10 min after unlock"),
        ["Menu.Hotkey"] = ("紧急热键 Ctrl+Alt+L", "Panic hotkey Ctrl+Alt+L"),
        ["Menu.WindowsHello"] = ("解锁时使用 Windows Hello", "Require Windows Hello on unlock"),
        ["Menu.CheckUpdate"] = ("检查更新", "Check for updates"),
        ["Menu.InstallService"] = ("安装守护服务（需管理员）", "Install guard service (admin)"),
        ["Menu.UninstallService"] = ("卸载守护服务", "Uninstall guard service"),
        ["Menu.Theme"] = ("主题", "Theme"),
        ["Menu.ThemeSystem"] = ("跟随系统", "Follow system"),
        ["Menu.ThemeDark"] = ("深色", "Dark"),
        ["Menu.ThemeLight"] = ("浅色", "Light"),
        ["Menu.Language"] = ("语言", "Language"),
        ["Menu.LanguageSystem"] = ("跟随系统", "Follow system"),
        ["Menu.LanguageZh"] = ("简体中文", "简体中文"),
        ["Menu.LanguageEn"] = ("English", "English"),
        ["Menu.ViewLogs"] = ("查看日志", "View log"),
        ["Menu.VaultTools"] = ("校验/救援容器", "Verify / salvage vault"),
        ["Menu.ExportKit"] = ("导出恢复套件", "Export recovery kit"),
        ["Menu.ImportKit"] = ("导入恢复套件", "Import recovery kit"),
        ["Menu.OpenDataDir"] = ("打开数据目录", "Open data folder"),
        ["Menu.SafetyInfo"] = ("安全说明", "Security notes"),
        ["Dialog.SetPassword"] = ("设置密码", "Set password"),
        ["Dialog.Lock"] = ("加锁", "Lock"),
        ["Dialog.Unlock"] = ("解锁", "Unlock"),
        ["Dialog.Remove"] = ("移除", "Remove"),
        ["Dialog.Verify"] = ("校验容器", "Verify vault"),
        ["Dialog.ExportKit"] = ("导出恢复套件", "Export recovery kit"),
        ["Dialog.ImportKit"] = ("导入恢复套件", "Import recovery kit"),
        ["Dialog.Password"] = ("密码", "Password"),
        ["Dialog.ConfirmPassword"] = ("确认密码", "Confirm password"),
        ["Dialog.CurrentPassword"] = ("当前密码", "Current password"),
        ["Dialog.NewPassword"] = ("新密码", "New password"),
        ["Dialog.ConfirmNewPassword"] = ("确认新密码", "Confirm new password"),
        ["Dialog.ChangePassword"] = ("修改密码", "Change password"),
        ["Dialog.Generate"] = ("生成随机密码", "Generate"),
        ["Dialog.Encrypt"] = ("使用 AES-256 加密，并安全擦除源文件与使用痕迹", "Use AES-256 encryption and wipe source files"),
        ["Dialog.Ok"] = ("确定", "OK"),
        ["Dialog.Cancel"] = ("取消", "Cancel"),
        ["Dialog.Copy"] = ("复制", "Copy"),
        ["Dialog.Saved"] = ("我已保存", "I've saved it"),
        ["Recovery.Title"] = ("恢复码", "Recovery code"),
        ["Recovery.Desc"] = ("请立即抄写并妥善保存以下恢复码。忘记密码时，可用它解锁加密文件夹。",
                             "Save this recovery code now. You can use it to unlock the encrypted folder if you forget the password."),
        ["Recovery.Copied"] = ("已复制到剪贴板。", "Copied to clipboard."),
        ["Recovery.CopyFailed"] = ("复制失败，请手动选择复制。", "Copy failed, please copy manually."),
        ["Log.Title"] = ("操作日志", "Activity log"),
        ["Log.Time"] = ("时间", "Time"),
        ["Log.Action"] = ("动作", "Action"),
        ["Log.Result"] = ("结果", "Result"),
        ["Log.Folder"] = ("文件夹", "Folder"),
        ["Log.Detail"] = ("详情", "Detail"),
        ["Log.Refresh"] = ("刷新", "Refresh"),
        ["Log.Export"] = ("导出 CSV", "Export CSV"),
        ["Log.Clear"] = ("清空", "Clear"),
        ["Log.Close"] = ("关闭", "Close"),
        ["Action.Add"] = ("添加", "Add"),
        ["Action.Lock"] = ("加锁", "Lock"),
        ["Action.Unlock"] = ("解锁", "Unlock"),
        ["Action.ChangePassword"] = ("修改密码", "Change password"),
        ["Action.Remove"] = ("移除", "Remove"),
        ["Action.FailedAttempt"] = ("密码错误", "Wrong password"),
        ["Action.AutoRelock"] = ("自动复锁", "Auto re-lock"),
        ["Action.TraceClean"] = ("清理痕迹", "Wipe traces"),
        ["Action.Success"] = ("成功", "OK"),
        ["Action.Failure"] = ("失败", "Failed"),
        ["Strength.0"] = ("强度：很弱", "Strength: very weak"),
        ["Strength.1"] = ("强度：弱", "Strength: weak"),
        ["Strength.2"] = ("强度：一般", "Strength: fair"),
        ["Strength.3"] = ("强度：强", "Strength: strong"),
        ["Strength.4"] = ("强度：很强", "Strength: very strong"),
    };

    private static string _language = Resolve(AppSettings.Current.Language);

    public static string Current => _language;

    public static void SetLanguage(string setting)
    {
        AppSettings.Current.Language = setting;
        AppSettings.Current.Save();
        _language = Resolve(setting);
    }

    public static string T(string key) =>
        Map.TryGetValue(key, out var value) ? (_language == "en" ? value.En : value.Zh) : key;

    public static string Format(string key, params object[] args) =>
        string.Format(CultureInfo.CurrentCulture, T(key), args);

    private static string Resolve(string setting) => setting switch
    {
        "English" => "en",
        "中文" => "zh",
        _ => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "zh" ? "zh" : "en",
    };
}

public sealed class LocExtension : MarkupExtension
{
    public LocExtension()
    {
    }

    public LocExtension(string key) => Key = key;

    public string Key { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider) => L.T(Key);
}
