using System.Security.AccessControl;
using System.Security.Principal;
using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class FolderLockerTests : IDisposable
{
    private readonly string _root;
    private readonly string _folder;
    private readonly string _file;
    private readonly FolderLocker _locker = new();
    private SecurityBackup? _backup;

    public FolderLockerTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Secret Folder");
        Directory.CreateDirectory(_folder);
        _file = Path.Combine(_folder, "note.txt");
        File.WriteAllText(_file, "top secret");
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
