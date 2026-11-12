using FolderLock.Core.Integration;
using Microsoft.Win32;

namespace FolderLock.App;

/// <summary>
/// 按 <see cref="ShellMenuSpec"/> 的定义写入/清理**平铺**右键菜单。
/// 默认写入 HKCU（无需管理员）；HKLM 需要管理员权限。
/// </summary>
public static class ShellIntegration
{
    private const string ClassesRoot = @"Software\Classes";

    public static void Install(ShellMenuScope scope = ShellMenuScope.CurrentUser)
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            throw new InvalidOperationException("无法确定程序路径。");
        }

        var definitions = ShellMenuSpec.ForDirectory(exe, L.Current)
            .Concat(ShellMenuSpec.ForVaultFile(exe, L.Current))
            .ToList();

        try
        {
            // 先清理同名子树与历史遗留键（旧级联/更旧平铺），确保不会产生重复菜单。
            foreach (var definition in definitions)
            {
                DeleteTree(scope, definition.KeyPath);
            }

            foreach (var legacy in ShellMenuSpec.LegacyKeyPaths)
            {
                DeleteTree(scope, legacy);
            }

            foreach (var definition in definitions)
            {
                WriteDefinition(scope, definition);
            }
        }
        catch
        {
            // 任何一步失败都回滚，避免留下半套菜单。
            foreach (var definition in definitions)
            {
                TryDeleteTree(scope, definition.KeyPath);
            }

            throw;
        }
    }

    public static void Uninstall(ShellMenuScope scope = ShellMenuScope.CurrentUser)
    {
        DeleteTree(scope, ShellMenuSpec.DirectoryLockKeyPath);
        DeleteTree(scope, ShellMenuSpec.DirectoryUnlockKeyPath);
        DeleteTree(scope, ShellMenuSpec.VaultFileKeyPath);

        foreach (var legacy in ShellMenuSpec.LegacyKeyPaths)
        {
            DeleteTree(scope, legacy);
        }
    }

    public static bool IsInstalled(ShellMenuScope scope = ShellMenuScope.CurrentUser)
    {
        using var key = Open(scope).OpenSubKey(PathUnderClasses(ShellMenuSpec.DirectoryLockKeyPath));
        return key is not null;
    }

    /// <summary>
    /// 平铺写法：verb 键（默认值=菜单文本、Icon、MultiSelectModel）+ command 子键。
    /// 平铺静态项在 Win11「显示更多选项」菜单中显示可靠（级联 SubCommands 有大量不显示的报告）。
    /// </summary>
    private static void WriteDefinition(ShellMenuScope scope, ShellMenuDefinition definition)
    {
        if (definition.Commands.Count != 1)
        {
            throw new InvalidOperationException(
                $"平铺菜单项只能包含一条命令（{definition.KeyPath} 有 {definition.Commands.Count} 条）。");
        }

        var command = definition.Commands[0];

        using var verb = Open(scope).CreateSubKey(PathUnderClasses(definition.KeyPath))
            ?? throw new InvalidOperationException($"无法创建右键菜单注册表键。");

        verb.SetValue(null, definition.DisplayName);
        verb.SetValue("Icon", definition.Icon);
        verb.SetValue("MultiSelectModel", ShellMenuSpec.MultiSelectModel);

        using var shellCommand = verb.CreateSubKey("command")
            ?? throw new InvalidOperationException($"无法创建菜单命令 {command.KeyName}。");
        shellCommand.SetValue(null, $"\"{definition.Icon}\" {command.Arguments}");
    }

    private static RegistryKey Open(ShellMenuScope scope) =>
        scope == ShellMenuScope.LocalMachine ? Registry.LocalMachine : Registry.CurrentUser;

    private static string PathUnderClasses(string relativePath) => $@"{ClassesRoot}\{relativePath}";

    private static void DeleteTree(ShellMenuScope scope, string keyPath)
    {
        Open(scope).DeleteSubKeyTree(PathUnderClasses(keyPath), throwOnMissingSubKey: false);
    }

    private static void TryDeleteTree(ShellMenuScope scope, string keyPath)
    {
        try
        {
            DeleteTree(scope, keyPath);
        }
        catch
        {
            // 回滚失败不覆盖原始异常。
        }
    }
}
