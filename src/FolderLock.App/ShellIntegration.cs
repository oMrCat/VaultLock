using Microsoft.Win32;

namespace FolderLock.App;

public static class ShellIntegration
{
    private const string ShellRoot = @"Software\Classes\Directory\shell";
    private const string AddKeyName = "FolderLock.Add";
    private const string LockKeyName = "FolderLock.Lock";
    private const string UnlockKeyName = "FolderLock.Unlock";

    public static void Install()
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            throw new InvalidOperationException("无法确定程序路径。");
        }

        CreateVerb(AddKeyName, "添加到 FolderLock 列表", exe, "--add");
        CreateVerb(LockKeyName, "用 FolderLock 加锁", exe, "--lock");
        CreateVerb(UnlockKeyName, "用 FolderLock 解锁", exe, "--unlock");
    }

    public static void Uninstall()
    {
        DeleteVerb(AddKeyName);
        DeleteVerb(LockKeyName);
        DeleteVerb(UnlockKeyName);
    }

    public static bool IsInstalled()
    {
        using var key = Registry.CurrentUser.OpenSubKey($@"{ShellRoot}\{LockKeyName}\command");
        return key is not null;
    }

    private static void CreateVerb(string keyName, string label, string exe, string verb)
    {
        using var key = Registry.CurrentUser.CreateSubKey($@"{ShellRoot}\{keyName}");
        key.SetValue(null, label);
        using var command = key.CreateSubKey("command");
        command.SetValue(null, $"\"{exe}\" {verb} \"%1\"");
    }

    private static void DeleteVerb(string keyName)
    {
        Registry.CurrentUser.DeleteSubKeyTree($@"{ShellRoot}\{keyName}", throwOnMissingSubKey: false);
    }
}
