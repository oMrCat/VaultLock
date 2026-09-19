using System.Text;
using FolderLock.Core.Update;

namespace FolderLock.Core.Tests.Update;

public class UpdaterTests
{
    [Theory]
    [InlineData("1.0.0", "1.0.1", true)]
    [InlineData("1.0.0", "1.1.0", true)]
    [InlineData("2.0.0", "1.9.9", false)]
    [InlineData("1.0.0", "1.0.0", false)]
    [InlineData("1.0.0", "not-a-version", false)]
    public void IsNewer_ComparesVersions(string current, string candidate, bool expected)
    {
        Assert.Equal(expected, Updater.IsNewer(current, candidate));
    }

    [Fact]
    public void VerifyHash_AcceptsMatchingHash()
    {
        var content = Encoding.UTF8.GetBytes("hello");
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content));

        Assert.Equal(expected, Updater.VerifyHash(content, expected));
    }

    [Fact]
    public void VerifyHash_RejectsMismatch()
    {
        var content = Encoding.UTF8.GetBytes("hello");

        Assert.Throws<InvalidOperationException>(() => Updater.VerifyHash(content, "DEADBEEF"));
    }

    [Fact]
    public async Task CheckAsync_ReturnsNullForEmptyUrl()
    {
        Assert.Null(await Updater.CheckAsync(string.Empty, "1.0.0"));
    }

    [Fact]
    public void UpdateManifest_DefaultsAreEmpty()
    {
        var manifest = new UpdateManifest();

        Assert.Equal(string.Empty, manifest.Version);
        Assert.Equal(string.Empty, manifest.Url);
    }
}
