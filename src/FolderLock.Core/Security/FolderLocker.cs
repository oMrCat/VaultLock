using System.Security.AccessControl;
using System.Security.Principal;

namespace FolderLock.Core.Security;

public enum FolderLockState
{
    Unlocked,
    Locked,

    /// <summary>无法判定（权限/IO 异常），调用方不应据此改写记录。</summary>
    Unknown,
}

public sealed record SecurityBackup(
    string DaclSddl,
    bool AccessRulesProtected,
    string? OwnerSid = null,
    uint? OriginalAttributes = null);

/// <summary>目录所有权/权限被接管，无法在不解锁的情况下恢复 DACL。</summary>
public sealed class FolderLockAccessException : Exception
{
    public FolderLockAccessException(string message)
        : base(message)
    {
    }

    public FolderLockAccessException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

public interface IFolderLocker
{
    SecurityBackup CaptureBackup(string path);

    void ApplyLock(string path, SecurityBackup backup);

    SecurityBackup Lock(string path);

    void Unlock(string path, SecurityBackup backup);

    FolderLockState GetLockState(string path);

    bool IsLocked(string path);
}

public sealed class FolderLocker : IFolderLocker
{
    private static readonly SecurityIdentifier WorldSid = new(WellKnownSidType.WorldSid, null);
    private static readonly FileAttributes LockMarkerAttributes = FileAttributes.Hidden | FileAttributes.System;

    public SecurityBackup CaptureBackup(string path)
    {
        var directory = GetDirectory(path);

        if (!NativeDirectoryAccess.CanChangePermissions(directory.FullName))
        {
            throw new FolderLockAccessException(
                $"当前进程对目录“{directory.FullName}”没有 WRITE_DAC 权限（目录所有者：{TryGetOwner(directory) ?? "未知"}），" +
                "已拒绝加锁以免形成“只能锁、不能解”的单向锁。请改用目录所有者账户运行，或以管理员取得所有权后重试。");
        }

        var security = directory.GetAccessControl(AccessControlSections.Access);
        return new SecurityBackup(
            security.GetSecurityDescriptorSddlForm(AccessControlSections.Access),
            security.AreAccessRulesProtected,
            TryGetOwner(directory),
            (uint)directory.Attributes);
    }

    public void ApplyLock(string path, SecurityBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);

        var directory = GetDirectory(path);

        if (!NativeDirectoryAccess.CanChangePermissions(directory.FullName))
        {
            throw new FolderLockAccessException(
                $"当前进程对目录“{directory.FullName}”没有 WRITE_DAC 权限，已拒绝加锁。" +
                "请改用目录所有者账户运行，或以管理员取得所有权后重试。");
        }

        var security = directory.GetAccessControl(AccessControlSections.Access);

        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: false,
                     targetType: typeof(SecurityIdentifier)))
        {
            security.RemoveAccessRuleSpecific(rule);
        }

        security.AddAccessRule(new FileSystemAccessRule(
            WorldSid,
            FileSystemRights.FullControl,
            AccessControlType.Deny));

        directory.Attributes |= LockMarkerAttributes;
        directory.SetAccessControl(security);
    }

    public SecurityBackup Lock(string path)
    {
        var backup = CaptureBackup(path);
        ApplyLock(path, backup);
        return backup;
    }

    public void Unlock(string path, SecurityBackup backup)
    {
        ArgumentNullException.ThrowIfNull(backup);

        var directory = GetDirectory(path);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(backup.DaclSddl, AccessControlSections.Access);

        if (!backup.AccessRulesProtected)
        {
            security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        }

        try
        {
            directory.SetAccessControl(security);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new FolderLockAccessException(
                $"无法恢复目录“{directory.FullName}”的权限：当前进程没有 WRITE_DAC，或目录所有权已被其他账户接管。",
                ex);
        }

        RestoreAttributes(directory, backup.OriginalAttributes);
    }

    public FolderLockState GetLockState(string path)
    {
        var directory = GetDirectory(path);

        DirectorySecurity security;
        try
        {
            security = directory.GetAccessControl(AccessControlSections.Access);
        }
        catch (UnauthorizedAccessException)
        {
            // 拒绝访问通常意味着 Deny Everyone 已生效：视为已锁定。
            return FolderLockState.Locked;
        }
        catch (IOException)
        {
            return FolderLockState.Unknown;
        }
        catch (SystemException)
        {
            return FolderLockState.Unknown;
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: false,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Deny &&
                rule.FileSystemRights == FileSystemRights.FullControl &&
                rule.IdentityReference is SecurityIdentifier sid &&
                sid.Equals(WorldSid))
            {
                return FolderLockState.Locked;
            }
        }

        return FolderLockState.Unlocked;
    }

    public bool IsLocked(string path) => GetLockState(path) == FolderLockState.Locked;

    private static void RestoreAttributes(DirectoryInfo directory, uint? originalAttributes)
    {
        var current = directory.Attributes;

        if (originalAttributes is { } original)
        {
            directory.Attributes = (current & ~LockMarkerAttributes) | ((FileAttributes)original & LockMarkerAttributes);
            return;
        }

        directory.Attributes &= ~LockMarkerAttributes;
    }

    private static string? TryGetOwner(DirectoryInfo directory)
    {
        try
        {
            var owner = directory.GetAccessControl(AccessControlSections.Owner)
                .GetOwner(typeof(SecurityIdentifier));
            return owner?.Value;
        }
        catch
        {
            return null;
        }
    }

    private static DirectoryInfo GetDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

        if (Path.GetPathRoot(fullPath) is { } root &&
            string.Equals(Path.TrimEndingDirectorySeparator(root), fullPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Cannot lock a drive root.", nameof(path));
        }

        var directory = new DirectoryInfo(fullPath);
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException($"Directory not found: {fullPath}");
        }

        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new ArgumentException("Cannot lock a reparse point or symbolic link.", nameof(path));
        }

        return directory;
    }
}
