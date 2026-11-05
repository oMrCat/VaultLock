namespace FolderLock.Core.Integration;

/// <summary>右键菜单写入范围：当前用户无需管理员，本机范围需要管理员。</summary>
public enum ShellMenuScope
{
    CurrentUser,
    LocalMachine,
}

/// <summary>级联菜单中的一个动词。</summary>
/// <param name="KeyName">子键名，前缀数字决定 Explorer 排序。</param>
/// <param name="Label">显示文本，已按语言本地化。</param>
/// <param name="Arguments">命令行参数模板，<c>%1</c> 由 Explorer 替换为选中路径。</param>
public sealed record ShellMenuCommand(string KeyName, string Label, string Arguments);

/// <summary>
/// 一个级联菜单的纯数据定义。由 <see cref="ShellMenuSpec"/> 生成，
/// 注册表写入交给 App 层，便于在不触碰注册表的情况下单测。
/// </summary>
/// <param name="KeyPath">相对 <c>Software\Classes</c> 的完整子键路径。</param>
/// <param name="DisplayName">级联父菜单的显示文本。</param>
/// <param name="Icon">图标来源（通常是程序自身路径）。</param>
/// <param name="Commands">级联子项。</param>
public sealed record ShellMenuDefinition(
    string KeyPath,
    string DisplayName,
    string Icon,
    IReadOnlyList<ShellMenuCommand> Commands);

/// <summary>
/// 右键菜单定义生成器：根据程序路径与语言生成文件夹、.flvault 两类级联菜单。
/// 不读写注册表，因此在 Core 层可直接单测键路径、标签与参数。
/// </summary>
public static class ShellMenuSpec
{
    public const string MenuKeyName = "VaultLock";

    /// <summary>Explorer 多选时把全部选中项作为参数传给同一命令。</summary>
    public const string MultiSelectModel = "Player";

    public const string DirectoryKeyPath = @"Directory\shell\VaultLock";

    public const string VaultFileKeyPath = @"SystemFileAssociations\.flvault\shell\VaultLock";

    /// <summary>旧版平铺菜单键名，安装/卸载时必须一并清理。</summary>
    public static readonly IReadOnlyList<string> LegacyKeyPaths = new[]
    {
        @"Directory\shell\FolderLock.Add",
        @"Directory\shell\FolderLock.Lock",
        @"Directory\shell\FolderLock.Unlock",
    };

    public static string ClassesRoot(ShellMenuScope scope) => scope switch
    {
        ShellMenuScope.LocalMachine => @"HKEY_LOCAL_MACHINE\Software\Classes",
        _ => @"HKEY_CURRENT_USER\Software\Classes",
    };

    /// <summary>文件夹右键菜单：加锁、解锁、纳入/移出列表、在主界面打开。</summary>
    public static ShellMenuDefinition ForDirectory(string executablePath, string language = "zh")
    {
        var labels = Labels.For(language);
        return new ShellMenuDefinition(
            DirectoryKeyPath,
            "VaultLock",
            executablePath,
            new[]
            {
                new ShellMenuCommand("01lock", labels.Lock, "--lock \"%1\""),
                new ShellMenuCommand("02unlock", labels.Unlock, "--unlock \"%1\""),
                new ShellMenuCommand("03add", labels.Add, "--add \"%1\""),
                new ShellMenuCommand("04remove", labels.Remove, "--remove \"%1\""),
                new ShellMenuCommand("05open", labels.Open, "--open \"%1\""),
            });
    }

    /// <summary>.flvault 文件右键菜单：验证、解密、抢救、在主界面打开。</summary>
    public static ShellMenuDefinition ForVaultFile(string executablePath, string language = "zh")
    {
        var labels = Labels.For(language);
        return new ShellMenuDefinition(
            VaultFileKeyPath,
            "VaultLock",
            executablePath,
            new[]
            {
                new ShellMenuCommand("01verify", labels.Verify, "--verify \"%1\""),
                new ShellMenuCommand("02decrypt", labels.Decrypt, "--decrypt \"%1\""),
                new ShellMenuCommand("03salvage", labels.Salvage, "--salvage \"%1\""),
                new ShellMenuCommand("04open", labels.Open, "--open \"%1\""),
            });
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
