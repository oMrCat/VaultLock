using System.Security.AccessControl;
using System.Security.Principal;
using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class FolderLockerTests : IDisposable
{
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    /// <summary>与 FolderLocker.ApplyLock 中 Deny Everyone 的权限位保持一致（去掉 WRITE_DAC）。</summary>
    private static readonly FileSystemRights LockDenyRights =
        FileSystemRights.FullControl & ~FileSystemRights.ChangePermissions;

    private readonly string _root;
    private readonly string _folder;
    private readonly string _file;
    private readonly string _nestedFolder;
    private readonly string _nestedFile;
    private readonly FolderLocker _locker = new();
    private SecurityBackup? _backup;

    public FolderLockerTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Secret Folder");
        Directory.CreateDirectory(_folder);
        _file = Path.Combine(_folder, "note.txt");
        File.WriteAllText(_file, "top secret");

        _nestedFolder = Path.Combine(_folder, "nested");
        Directory.CreateDirectory(_nestedFolder);
        _nestedFile = Path.Combine(_nestedFolder, "deep.txt");
        File.WriteAllText(_nestedFile, "deep secret");
    }

    [Fact]
    public void Lock_MarksFolderLockedAndHidesIt()
    {
        _backup = _locker.Lock(_folder);

        Assert.True(_locker.IsLocked(_folder));
        var attributes = new DirectoryInfo(_folder).Attributes;
        Assert.True(attributes.HasFlag(FileAttributes.Hidden));
        Assert.True(attributes.HasFlag(FileAttributes.System));
    }

    [Fact]
    public void Lock_BlocksReadingContainedFiles()
    {
        _backup = _locker.Lock(_folder);

        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(_file));
    }

    [Fact]
    public void Lock_BlocksReadingNestedContainedFiles()
    {
        _backup = _locker.Lock(_folder);

        // 锁规则带 OI|CI 标志，必须能穿透一层子目录作用到更深层的文件。
        Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(_nestedFile));
    }

    [Fact]
    public void Lock_CutsInheritanceAndInstallsOnlyTwoLockRules()
    {
        _backup = _locker.Lock(_folder);

        var security = new DirectoryInfo(_folder).GetAccessControl(AccessControlSections.Access);

        // 切断继承，避免原始 Allow 规则先于 Deny 生效。
        Assert.True(security.AreAccessRulesProtected);

        var rules = GetExplicitRules(security);
        Assert.Equal(2, rules.Count);

        // Synchronize 位不会被 Windows 持久化到 ACE 中，比较时忽略。
        var expectedDeny = LockDenyRights & ~FileSystemRights.Synchronize;

        var deny = Assert.Single(rules, rule => rule.AccessControlType == AccessControlType.Deny);
        Assert.Equal(Everyone.Value, ((SecurityIdentifier)deny.IdentityReference).Value);
        Assert.Equal(expectedDeny, deny.FileSystemRights);
        Assert.Equal(InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, deny.InheritanceFlags);

        // 保留 WRITE_DAC，Unlock 才能在同进程内还原原始 DACL。
        var allow = Assert.Single(rules, rule => rule.AccessControlType == AccessControlType.Allow);
        Assert.Equal(Everyone.Value, ((SecurityIdentifier)allow.IdentityReference).Value);
        Assert.Equal(FileSystemRights.ChangePermissions, allow.FileSystemRights & ~FileSystemRights.Synchronize);
        Assert.Equal(InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, allow.InheritanceFlags);
    }

    [Fact]
    public void Unlock_RestoresAccessAndAttributes()
    {
        _backup = _locker.Lock(_folder);
        _locker.Unlock(_folder, _backup);
        _backup = null;

        Assert.False(_locker.IsLocked(_folder));
        Assert.Equal("top secret", File.ReadAllText(_file));
        var attributes = new DirectoryInfo(_folder).Attributes;
        Assert.False(attributes.HasFlag(FileAttributes.Hidden));
        Assert.False(attributes.HasFlag(FileAttributes.System));
    }

    [Fact]
    public void Unlock_RestoresOriginalDacl()
    {
        var original = new DirectoryInfo(_folder).GetAccessControl(AccessControlSections.Access);
        var originalRules = DescribeExplicitRules(original);
        var originalProtected = original.AreAccessRulesProtected;

        _backup = _locker.Lock(_folder);
        _locker.Unlock(_folder, _backup);
        _backup = null;

        var restored = new DirectoryInfo(_folder).GetAccessControl(AccessControlSections.Access);

        // Compare the effective access rules rather than the raw descriptor SDDL:
        // Windows re-applies the SE_DACL_AUTO_INHERITED control flag on restore,
        // which is not a behavioral difference.
        Assert.Equal(originalRules, DescribeExplicitRules(restored));
        Assert.Equal(originalProtected, restored.AreAccessRulesProtected);
        Assert.False(_locker.IsLocked(_folder));
    }

    [Fact]
    public void Unlock_RestoresAccessToNestedFilesAndFolders()
    {
        _backup = _locker.Lock(_folder);
        _locker.Unlock(_folder, _backup);
        _backup = null;

        Assert.Equal("deep secret", File.ReadAllText(_nestedFile));
        Assert.Single(Directory.GetFiles(_nestedFolder));
    }

    [Fact]
    public void Unlock_LeavesNoResidualLockRulesOnNestedItems()
    {
        _backup = _locker.Lock(_folder);
        _locker.Unlock(_folder, _backup);
        _backup = null;

        // 关键回归点：切断继承时若锁规则没有 OI|CI 标志，子项的锁规则会被固化成显式 ACE，
        // 之后即使还原了目录 DACL，子文件仍然不可读。这里断言子项只剩继承规则。
        var childFile = new FileInfo(_nestedFile).GetAccessControl(AccessControlSections.Access);
        var childFolder = new DirectoryInfo(_nestedFolder).GetAccessControl(AccessControlSections.Access);

        Assert.Empty(GetExplicitRules(childFile));
        Assert.Empty(GetExplicitRules(childFolder));
    }

    private static List<FileSystemAccessRule> GetExplicitRules(FileSystemSecurity security)
    {
        return security
            .GetAccessRules(includeExplicit: true, includeInherited: false, targetType: typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToList();
    }

    private static List<string> DescribeExplicitRules(DirectorySecurity security)
    {
        return security
            .GetAccessRules(includeExplicit: true, includeInherited: false, targetType: typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(rule =>
                $"{rule.IdentityReference.Value}|{rule.AccessControlType}|{rule.FileSystemRights}|{rule.InheritanceFlags}|{rule.PropagationFlags}")
            .OrderBy(text => text, StringComparer.Ordinal)
            .ToList();
    }

    [Fact]
    public void IsLocked_ReturnsFalseForUnlockedFolder()
    {
        Assert.False(_locker.IsLocked(_folder));
    }

    [Fact]
    public void Lock_ThrowsForMissingDirectory()
    {
        var missing = Path.Combine(_root, "missing");

        Assert.Throws<DirectoryNotFoundException>(() => _locker.Lock(missing));
    }

    [Fact]
    public void Lock_ThrowsForDriveRoot()
    {
        var root = Path.GetPathRoot(_root)!;

        Assert.Throws<ArgumentException>(() => _locker.Lock(root));
    }

    public void Dispose()
    {
        if (_backup is not null)
        {
            try
            {
                _locker.Unlock(_folder, _backup);
            }
            catch
            {
            }
        }

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }
}
