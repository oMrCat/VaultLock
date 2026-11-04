using FolderLock.Core.Security;
using FolderLock.Core.Update;

namespace FolderLock.Core.Tests.Update;

public sealed class UpdaterSecurityTests
{
    [Fact]
    public void ValidateManifest_RejectsPlainHttp()
    {
        var manifest = new UpdateManifest
        {
            Version = "2.0.0",
            Url = "http://example.com/app.zip",
            Sha256 = new string('a', 64),
        };

        var error = Updater.ValidateManifest(manifest);
        Assert.NotNull(error);
        Assert.Contains("HTTPS", error);
    }

    [Fact]
    public void ValidateManifest_RequiresSha256()
    {
        var manifest = new UpdateManifest
        {
            Version = "2.0.0",
            Url = "https://example.com/app.zip",
            Sha256 = string.Empty,
        };

        var error = Updater.ValidateManifest(manifest);
        Assert.NotNull(error);
        Assert.Contains("SHA-256", error);

        manifest.Sha256 = "xyz";
        Assert.Contains("SHA-256", Updater.ValidateManifest(manifest));
    }

    [Fact]
    public void ValidateManifest_AcceptsHttpsWithHash()
    {
        var manifest = new UpdateManifest
        {
            Version = "2.0.0",
            Url = "https://example.com/app.zip",
            Sha256 = new string('a', 64),
        };

        Assert.Null(Updater.ValidateManifest(manifest));
    }

    [Fact]
    public async Task DownloadAsync_RejectsInsecureManifestBeforeAnyRequest()
    {
        var manifest = new UpdateManifest
        {
            Version = "2.0.0",
            Url = "http://example.com/app.zip",
            Sha256 = new string('a', 64),
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Updater.DownloadAsync(manifest, Path.Combine(Path.GetTempPath(), "should-not-exist.exe")));
    }

    [Fact]
    public void GetStatus_EmbeddedSignedSystemBinaryIsValid()
    {
        // 注意：WinVerifyTrust(WTD_CHOICE_FILE) 只识别“嵌入签名”（如 kernel32.dll）；
        // 仅由目录（catalog）签名的文件（notepad.exe/cmd.exe）会被视为未签名，这是本实现的已知边界。
        var signed = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "kernel32.dll");

        Assert.True(File.Exists(signed), "当前环境缺少 kernel32.dll，无法验证签名信任链。");
        Assert.Equal(AuthenticodeStatus.Valid, Authenticode.GetStatus(signed));
    }

    [Fact]
    public void GetStatus_InvalidPeFileIsNotConsideredTrusted()
    {
        var path = Path.Combine(Path.GetTempPath(), $"folderlock-unsigned-{Guid.NewGuid():N}.exe");

        try
        {
            File.WriteAllBytes(path, new byte[] { (byte)'M', (byte)'Z', 0, 0 });
            Assert.NotEqual(AuthenticodeStatus.Valid, Authenticode.GetStatus(path));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
