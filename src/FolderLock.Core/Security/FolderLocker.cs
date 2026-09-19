using System.Security.AccessControl;
using System.Security.Principal;

namespace FolderLock.Core.Security;

public enum FolderLockState
{
    Unlocked,
    Locked,
}

public sealed record SecurityBackup(string DaclSddl, bool AccessRulesProtected);

public interface IFolderLocker
{
    SecurityBackup Lock(string path);

    void Unlock(string path, SecurityBackup backup);

    bool IsLocked(string path);
}

public sealed class FolderLocker : IFolderLocker
{
    private static readonly SecurityIdentifier WorldSid = new(WellKnownSidType.WorldSid, null);

    public SecurityBackup Lock(string path)
    {
        var directory = GetDirectory(path);
        var security = directory.GetAccessControl(AccessControlSections.Access);
        var backup = new SecurityBackup(
            security.GetSecurityDescriptorSddlForm(AccessControlSections.Access),
            security.AreAccessRulesProtected);

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

        directory.Attributes |= FileAttributes.Hidden | FileAttributes.System;
        directory.SetAccessControl(security);

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

        directory.SetAccessControl(security);
        directory.Attributes &= ~(FileAttributes.Hidden | FileAttributes.System);
    }

    public bool IsLocked(string path)
    {
        var directory = GetDirectory(path);

        DirectorySecurity security;
        try
        {
            security = directory.GetAccessControl(AccessControlSections.Access);
        }
        catch (UnauthorizedAccessException)
        {
            return true;
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
                return true;
            }
        }

        return false;
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
