using FolderLock.Core.Integration;
using Microsoft.Win32;

namespace FolderLock.App;

/// <summary>
/// 按 <see cref="ShellMenuSpec"/> 的定义写入/清理级联右键菜单。
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

        var definitions = new[]
        {
            ShellMenuSpec.ForDirectory(exe, L.Current),
            ShellMenuSpec.ForVaultFile(exe, L.Current),
        };

        try
        {
            // 先清理同名子树与旧版平铺条目，确保重复安装不会产生重复菜单。
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
        DeleteTree(scope, ShellMenuSpec.DirectoryKeyPath);
        DeleteTree(scope, ShellMenuSpec.VaultFileKeyPath);

        foreach (var legacy in ShellMenuSpec.LegacyKeyPaths)
        {
            DeleteTree(scope, legacy);
        }
    }

    public static bool IsInstalled(ShellMenuScope scope = ShellMenuScope.CurrentUser)
    {
        using var key = Open(scope).OpenSubKey(PathUnderClasses(ShellMenuSpec.DirectoryKeyPath));
        return key is not null;
    }

    private static void WriteDefinition(ShellMenuScope scope, ShellMenuDefinition definition)
    {
        using var parent = Open(scope).CreateSubKey(PathUnderClasses(definition.KeyPath))
            ?? throw new InvalidOperationException("无法创建右键菜单注册表键。");

        parent.SetValue(null, definition.DisplayName);
        parent.SetValue("Icon", definition.Icon);

        // 级联父菜单必须设置空的 SubCommands，且父键本身不能有 command 子键。
        parent.SetValue("SubCommands", string.Empty);

        foreach (var command in definition.Commands)
        {
            using var verb = parent.CreateSubKey($@"shell\{command.KeyName}")
                ?? throw new InvalidOperationException($"无法创建菜单项 {command.KeyName}。");
            verb.SetValue(null, command.Label);

            // 多选时一次性传入全部选中项，由应用逐个处理。
            verb.SetValue("MultiSelectModel", ShellMenuSpec.MultiSelectModel);

            using var shellCommand = verb.CreateSubKey("command")
                ?? throw new InvalidOperationException($"无法创建菜单命令 {command.KeyName}。");
            shellCommand.SetValue(null, $"\"{definition.Icon}\" {command.Arguments}");
        }
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
