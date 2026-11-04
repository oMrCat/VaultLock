using System.Security.AccessControl;
using System.Security.Principal;
using FolderLock.Core.Services;

namespace FolderLock.Core.Data;

/// <summary>
/// 守护服务侧对 watchlist 条目的信任校验：拒绝系统目录、reparse point，
/// 以及所有者不是普通用户（SYSTEM/服务账户等）的目录，避免被篡改的列表诱导服务操作敏感路径。
/// </summary>
public static class WatchlistEntryValidator
{
    private static readonly HashSet<string> NonUserOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "S-1-5-18", // SYSTEM
        "S-1-5-19", // LOCAL SERVICE
        "S-1-5-20", // NETWORK SERVICE
        "S-1-5-7",  // ANONYMOUS LOGON
        "S-1-1-0",  // Everyone
    };

    public static bool TryValidate(string path, out string reason)
    {
        reason = string.Empty;

        if (PathGuard.TryGetBlockReason(path, out reason))
        {
            return false;
        }

        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

        if (!Directory.Exists(full))
        {
            reason = $"目录不存在：{full}";
            return false;
        }

        try
        {
            var directory = new DirectoryInfo(full);
            if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                reason = $"目录是 reparse point/符号链接，已跳过：{full}";
                return false;
            }

            var owner = directory.GetAccessControl(AccessControlSections.Owner)
                .GetOwner(typeof(SecurityIdentifier));

            if (owner is null)
            {
                reason = $"无法确定目录所有者：{full}";
                return false;
            }

            if (NonUserOwners.Contains(owner.Value))
            {
                reason = $"目录所有者不是普通用户账户（{owner.Value}），已跳过：{full}";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            reason = $"校验目录 {full} 失败：{ex.Message}";
            return false;
        }
    }
}
