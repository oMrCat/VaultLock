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

    [Fact]
    public void VerifyStagedFile_RejectsMissingFile()
    {
        var path = Path.Combine(Path.GetTempPath(), "folderlock-missing-" + Guid.NewGuid().ToString("N") + ".exe");

        Assert.Throws<InvalidOperationException>(() => Updater.VerifyStagedFile(path, null));
    }

    [Fact]
    public void VerifyStagedFile_RejectsNonExecutableContent()
    {
        var path = Path.Combine(Path.GetTempPath(), "folderlock-bad-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(path, new string('x', 128));

        try
        {
            Assert.Throws<InvalidOperationException>(() => Updater.VerifyStagedFile(path, null));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void VerifyStagedFile_AcceptsExecutableAndRejectsHashMismatch()
    {
        var content = new byte[128];
        content[0] = (byte)'M';
        content[1] = (byte)'Z';
        var path = Path.Combine(Path.GetTempPath(), "folderlock-good-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllBytes(path, content);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content));

        try
        {
            // 测试夹具没有 Authenticode 签名，显式关闭签名要求以验证哈希逻辑。
            Assert.Equal(hash, Updater.VerifyStagedFile(path, hash, requireSignature: false));
            Assert.Throws<InvalidOperationException>(
                () => Updater.VerifyStagedFile(path, "DEADBEEF", requireSignature: false));

            // 默认策略必须拒绝未签名文件。
            Assert.Throws<InvalidOperationException>(() => Updater.VerifyStagedFile(path, hash));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void BuildApplyScript_WaitsForProcessAndReportsCopyFailure()
    {
        var script = Updater.BuildApplyScript(
            @"C:\Temp\FolderLock.new.exe",
            @"C:\Apps\FolderLock.exe",
            @"C:\Data\update-result.txt",
            4321);

        Assert.Contains("Get-Process -Id 4321", script);
        Assert.Contains(":copy_retry", script);
        Assert.Contains("GEQ 5", script);
        Assert.Contains("echo failed", script);
        Assert.Contains("echo ok", script);
        Assert.Contains(@"C:\Data\update-result.txt", script);
        Assert.DoesNotContain("timeout /t 1 /nobreak >nul\r\ncopy", script);
    }
}
