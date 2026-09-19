using FolderLock.Core.Integration;

namespace FolderLock.Core.Tests.Integration;

public class OverlayAdvisorTests
{
    private static readonly string[] Locked =
    {
        @"C:\Data\Secret",
        @"C:\Vaults\Hidden",
    };

    [Fact]
    public void ExactFolderShowsLocked()
    {
        Assert.Equal(OverlayKind.Locked, OverlayAdvisor.GetOverlay(@"C:\Data\Secret", Locked));
    }

    [Fact]
    public void ChildFolderShowsLocked()
    {
        Assert.Equal(OverlayKind.Locked, OverlayAdvisor.GetOverlay(@"C:\Data\Secret\sub\deep", Locked));
    }

    [Fact]
    public void UnrelatedFolderShowsNone()
    {
        Assert.Equal(OverlayKind.None, OverlayAdvisor.GetOverlay(@"C:\Data\Public", Locked));
    }

    [Fact]
    public void PartialNamePrefixIsNotMatched()
    {
        // "Secret2" must not match "Secret".
        Assert.Equal(OverlayKind.None, OverlayAdvisor.GetOverlay(@"C:\Data\Secret2", Locked));
    }

    [Fact]
    public void IsCaseInsensitive()
    {
        Assert.Equal(OverlayKind.Locked, OverlayAdvisor.GetOverlay(@"c:\data\secret", Locked));
    }

    [Fact]
    public void TrailingSeparatorIsHandled()
    {
        Assert.Equal(OverlayKind.Locked, OverlayAdvisor.GetOverlay(@"C:\Data\Secret\", Locked));
    }
}
