using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public class PathGuardTests
{
    [Fact]
    public void TempFolderIsAllowed()
    {
        var temp = Path.Combine(Path.GetTempPath(), "FolderLockTests", "allowed");

        Assert.False(PathGuard.TryGetBlockReason(temp, out _));
    }

    [Fact]
    public void NormalUserFolderIsAllowed()
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents", "MyVault");

        Assert.False(PathGuard.TryGetBlockReason(folder, out _));
    }

    [Fact]
    public void DriveRootIsBlocked()
    {
        var root = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))!;

        Assert.True(PathGuard.TryGetBlockReason(root, out _));
    }

    [Theory]
    [InlineData(Environment.SpecialFolder.Windows)]
    [InlineData(Environment.SpecialFolder.ProgramFiles)]
    [InlineData(Environment.SpecialFolder.ProgramFilesX86)]
    [InlineData(Environment.SpecialFolder.UserProfile)]
    [InlineData(Environment.SpecialFolder.MyDocuments)]
    [InlineData(Environment.SpecialFolder.DesktopDirectory)]
    public void ProtectedRootsAreBlocked(Environment.SpecialFolder folder)
    {
        var path = Environment.GetFolderPath(folder);
        Assert.False(string.IsNullOrWhiteSpace(path), $"当前环境缺少 {folder} 路径，无法验证保护规则。");

        Assert.True(PathGuard.TryGetBlockReason(path, out _));
    }

    [Fact]
    public void FolderInsideWindowsIsBlocked()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.False(string.IsNullOrWhiteSpace(windows), "当前环境缺少 Windows 目录，无法验证保护规则。");

        Assert.True(PathGuard.TryGetBlockReason(Path.Combine(windows, "System32"), out _));
    }

    [Fact]
    public void AncestorOfUserProfileIsBlocked()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var parent = Directory.GetParent(profile);
        Assert.NotNull(parent);
        Assert.True(PathGuard.TryGetBlockReason(parent!.FullName, out _));
    }

    [Fact]
    public void EnsureLockableThrowsForProtectedPath()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.False(string.IsNullOrWhiteSpace(windows), "当前环境缺少 Windows 目录，无法验证保护规则。");

        Assert.Throws<FolderLockException>(() => PathGuard.EnsureLockable(windows));
    }
}
