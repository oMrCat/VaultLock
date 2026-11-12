namespace FolderLock.Core.Integration;

/// <summary>右键菜单写入范围：当前用户无需管理员，本机范围需要管理员。</summary>
public enum ShellMenuScope
{
    CurrentUser,
    LocalMachine,
}

/// <summary>平铺菜单中的一个动词。</summary>
/// <param name="KeyName">子键名，前缀数字决定 Explorer 排序。</param>
/// <param name="Label">显示文本，已按语言本地化。</param>
/// <param name="Arguments">命令行参数模板，<c>%1</c> 由 Explorer 替换为选中路径。</param>
public sealed record ShellMenuCommand(string KeyName, string Label, string Arguments);

/// <summary>
/// 一个右键菜单项的纯数据定义。由 <see cref="ShellMenuSpec"/> 生成，
/// 注册表写入交给 App 层，便于在不触碰注册表的情况下单测键路径、标签与参数。
/// </summary>
/// <param name="KeyPath">相对 <c>Software\Classes</c> 的完整 verb 子键路径。</param>
/// <param name="DisplayName">菜单显示文本。</param>
/// <param name="Icon">图标来源（通常是程序自身路径）。</param>
/// <param name="Commands">该菜单项的命令（平铺项恰好一个）。</param>
public sealed record ShellMenuDefinition(
    string KeyPath,
    string DisplayName,
    string Icon,
    IReadOnlyList<ShellMenuCommand> Commands);

/// <summary>
/// 右键菜单定义生成器：根据程序路径与语言生成**平铺**菜单项。
///
/// 为什么是平铺而不是级联（SubCommands）：Windows 11 的现代右键菜单不显示
/// classic 项；即使在「显示更多选项」旧菜单里，静态注册的**级联**项也大量
/// 存在不显示的报告，而**平铺**静态项显示可靠。因此只暴露加锁/解锁两个
/// 高频动作（低频动作走主界面），每个动作一个独立顶层项。
///
/// 不读写注册表，因此在 Core 层可直接单测键路径、标签与参数。
/// </summary>
public static class ShellMenuSpec
{
    public const string MenuKeyName = "VaultLock";

    /// <summary>Explorer 多选时把全部选中项作为参数传给同一命令。</summary>
    public const string MultiSelectModel = "Player";

    public const string DirectoryLockKeyPath = @"Directory\shell\VaultLock.Lock";
    public const string DirectoryUnlockKeyPath = @"Directory\shell\VaultLock.Unlock";
    public const string VaultFileKeyPath = @"SystemFileAssociations\.flvault\shell\VaultLock.Open";

    /// <summary>历史遗留键（旧级联/更旧平铺），安装/卸载时必须一并清理。</summary>
    public static readonly IReadOnlyList<string> LegacyKeyPaths = new[]
    {
        @"Directory\shell\VaultLock",
        @"SystemFileAssociations\.flvault\shell\VaultLock",
        @"Directory\shell\FolderLock.Add",
        @"Directory\shell\FolderLock.Lock",
        @"Directory\shell\FolderLock.Unlock",
    };

    public static string ClassesRoot(ShellMenuScope scope) => scope switch
    {
        ShellMenuScope.LocalMachine => @"HKEY_LOCAL_MACHINE\Software\Classes",
        _ => @"HKEY_CURRENT_USER\Software\Classes",
    };

    /// <summary>文件夹右键：加锁、解锁两个高频动作（平铺）。</summary>
    public static IReadOnlyList<ShellMenuDefinition> ForDirectory(string executablePath, string language = "zh")
    {
        var labels = Labels.For(language);
        return new[]
        {
            new ShellMenuDefinition(
                DirectoryLockKeyPath,
                $"VaultLock：{labels.Lock}",
                executablePath,
                new[] { new ShellMenuCommand("lock", labels.Lock, "--lock \"%1\"") }),
            new ShellMenuDefinition(
                DirectoryUnlockKeyPath,
                $"VaultLock：{labels.Unlock}",
                executablePath,
                new[] { new ShellMenuCommand("unlock", labels.Unlock, "--unlock \"%1\"") }),
        };
    }

    /// <summary>.flvault 文件右键：在主界面打开（平铺）。</summary>
    public static IReadOnlyList<ShellMenuDefinition> ForVaultFile(string executablePath, string language = "zh")
    {
        var labels = Labels.For(language);
        return new[]
        {
            new ShellMenuDefinition(
                VaultFileKeyPath,
                $"VaultLock：{labels.Open}",
                executablePath,
                new[] { new ShellMenuCommand("open", labels.Open, "--open \"%1\"") }),
        };
    }

    private sealed record MenuLabels(
        string Lock,
        string Unlock,
        string Add,
        string Remove,
        string Open,
        string Verify,
        string Decrypt,
        string Salvage);

    private static class Labels
    {
        private static readonly MenuLabels Zh = new(
            "加锁",
            "解锁",
            "加入保护列表",
            "移出保护列表",
            "在 VaultLock 中打开",
            "验证容器",
            "解密到文件夹",
            "抢救容器");

        private static readonly MenuLabels En = new(
            "Lock",
            "Unlock",
            "Add to protection list",
            "Remove from protection list",
            "Open in VaultLock",
            "Verify vault",
            "Decrypt to folder",
            "Salvage vault");

        public static MenuLabels For(string language) =>
            string.Equals(language, "en", StringComparison.OrdinalIgnoreCase) ? En : Zh;
    }
}
