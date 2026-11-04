using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class AuthenticodePolicyTests : IDisposable
{
    private const string EnvironmentVariable = AuthenticodePolicy.PublisherEnvironmentVariable;

    private readonly string? _originalValue;
    private readonly string _unsignedFile;

    public AuthenticodePolicyTests()
    {
        _originalValue = Environment.GetEnvironmentVariable(EnvironmentVariable);
        _unsignedFile = Path.Combine(Path.GetTempPath(), $"folderlock-unsigned-{Guid.NewGuid():N}.exe");
        File.WriteAllText(_unsignedFile, "not a signed binary");
    }

    [Fact]
    public void Matches_IgnoresCaseAndWhitespace()
    {
        Assert.True(AuthenticodePolicy.Matches(
            "CN=FolderLock, O=Example",
            ["cn=folderlock,o=example"]));
        Assert.True(AuthenticodePolicy.Matches(
            "CN=FolderLock Test Signing",
            [" CN = FolderLockTestSigning "]));
    }

    [Fact]
    public void Matches_RejectsDifferentPublisher()
    {
        Assert.False(AuthenticodePolicy.Matches(
            "CN=FolderLock, O=Example",
            ["CN=Someone Else"]));
        Assert.False(AuthenticodePolicy.Matches(null, ["CN=FolderLock"]));
    }

    [Fact]
    public void Check_UnsignedFileIsNeverTrusted()
    {
        SetPublisher("CN=FolderLock");

        var check = AuthenticodePolicy.Check(_unsignedFile);

        Assert.False(check.IsTrusted);
        Assert.NotEqual(AuthenticodeStatus.Valid, check.Status);
    }

    [Fact]
    public void Check_ValidSignatureFromUnexpectedPublisherIsRejected()
    {
        var signed = GetSignedSystemFile();
        SetPublisher("CN=Totally Different Publisher");

        var check = AuthenticodePolicy.Check(signed);

        Assert.Equal(AuthenticodeStatus.Valid, check.Status);
        Assert.Equal(PublisherTrust.Mismatched, check.Publisher);
        Assert.False(check.IsTrusted);
    }

    [Fact]
    public void Check_ValidSignatureMatchingConfiguredPublisherIsTrusted()
    {
        var signed = GetSignedSystemFile();
        var subject = Authenticode.GetSignerSubject(signed);

        Assert.False(string.IsNullOrWhiteSpace(subject), "无法读取系统文件的签名者主题。");
        SetPublisher(subject);

        var check = AuthenticodePolicy.Check(signed);

        Assert.Equal(PublisherTrust.Matched, check.Publisher);
        Assert.True(check.IsTrusted);
    }

    [Fact]
    public void Check_ValidSignatureWithoutConfigurationIsTrustedAndWarns()
    {
        SetPublisher(null);

        var check = AuthenticodePolicy.Check(GetSignedSystemFile());

        Assert.Equal(PublisherTrust.NotConfigured, check.Publisher);
        Assert.True(check.IsTrusted);
        Assert.Contains("未配置", check.Message);
    }

    [Fact]
    public void LoadExpectedPublishers_SplitsEnvironmentVariable()
    {
        SetPublisher("CN=A; CN=B\nCN=C");

        var publishers = AuthenticodePolicy.LoadExpectedPublishers();

        Assert.Equal(new[] { "CN=A", "CN=B", "CN=C" }, publishers);
    }

    private static string GetSignedSystemFile()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "kernel32.dll");

        Assert.True(File.Exists(path), "当前环境缺少 kernel32.dll，无法验证签名信任链。");
        return path;
    }

    private static void SetPublisher(string? value)
    {
        Environment.SetEnvironmentVariable(EnvironmentVariable, value);
    }

    public void Dispose()
    {
        SetPublisher(_originalValue);

        try
        {
            File.Delete(_unsignedFile);
        }
        catch
        {
        }
    }
}
