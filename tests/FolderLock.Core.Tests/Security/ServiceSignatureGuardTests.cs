using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class ServiceSignatureGuardTests
{
    private static AuthenticodeCheck Check(
        AuthenticodeStatus status,
        PublisherTrust publisher = PublisherTrust.NotConfigured,
        string? subject = null) =>
        new(status, subject, publisher, "签名详情");

    [Theory]
    [InlineData(AuthenticodeStatus.NotSigned)]
    [InlineData(AuthenticodeStatus.Invalid)]
    [InlineData(AuthenticodeStatus.Error)]
    public void WarnMode_AllowsUntrustedSignatureAndLogsWarning(AuthenticodeStatus status)
    {
        var decision = ServiceSignatureGuard.Evaluate(Check(status), SignatureEnforcementMode.Warn);

        Assert.Equal(ServiceStartupDecision.Allow, decision.Decision);
        Assert.Equal(ServiceSignatureGuard.WarningLevel, decision.Level);
        Assert.Contains("警告模式", decision.Message);
        Assert.Contains("继续启动", decision.Message);
    }

    [Fact]
    public void WarnMode_AllowsPublisherMismatchAndLogsWarning()
    {
        var decision = ServiceSignatureGuard.Evaluate(
            Check(AuthenticodeStatus.Valid, PublisherTrust.Mismatched, "CN=Unexpected"),
            SignatureEnforcementMode.Warn);

        Assert.Equal(ServiceStartupDecision.Allow, decision.Decision);
        Assert.Equal(ServiceSignatureGuard.WarningLevel, decision.Level);
        Assert.Contains("警告模式", decision.Message);
        Assert.Contains("签名详情", decision.Message);
    }

    [Fact]
    public void WarnMode_ValidSignatureWithMatchingPublisherLogsInfo()
    {
        var decision = ServiceSignatureGuard.Evaluate(
            Check(AuthenticodeStatus.Valid, PublisherTrust.Matched, "CN=FolderLock"),
            SignatureEnforcementMode.Warn);

        Assert.Equal(ServiceStartupDecision.Allow, decision.Decision);
        Assert.Equal(ServiceSignatureGuard.InfoLevel, decision.Level);
        Assert.Contains("签名校验通过", decision.Message);
        Assert.Contains("CN=FolderLock", decision.Message);
    }

    [Fact]
    public void WarnMode_ValidSignatureWithoutPublisherPinningLogsWarning()
    {
        var decision = ServiceSignatureGuard.Evaluate(
            Check(AuthenticodeStatus.Valid, PublisherTrust.NotConfigured, "CN=FolderLock"),
            SignatureEnforcementMode.Warn);

        Assert.Equal(ServiceStartupDecision.Allow, decision.Decision);
        Assert.Equal(ServiceSignatureGuard.WarningLevel, decision.Level);
        Assert.Contains("发布者固定校验未生效", decision.Message);
    }

    [Fact]
    public void StrictMode_RefusesUnsignedService()
    {
        var decision = ServiceSignatureGuard.Evaluate(
            Check(AuthenticodeStatus.NotSigned),
            SignatureEnforcementMode.Strict);

        Assert.True(decision.IsRefused);
        Assert.Equal(ServiceStartupDecision.Refuse, decision.Decision);
        Assert.Equal(ServiceSignatureGuard.ErrorLevel, decision.Level);
        Assert.Contains("严格", decision.Message);
        Assert.Contains("拒绝启动", decision.Message);
    }

    [Fact]
    public void StrictMode_RefusesPublisherMismatch()
    {
        var decision = ServiceSignatureGuard.Evaluate(
            Check(AuthenticodeStatus.Valid, PublisherTrust.Mismatched, "CN=Unexpected"),
            SignatureEnforcementMode.Strict);

        Assert.True(decision.IsRefused);
        Assert.Equal(ServiceSignatureGuard.ErrorLevel, decision.Level);
        Assert.Contains("拒绝启动", decision.Message);
    }

    [Fact]
    public void StrictMode_AllowsTrustedSignature()
    {
        var decision = ServiceSignatureGuard.Evaluate(
            Check(AuthenticodeStatus.Valid, PublisherTrust.Matched, "CN=FolderLock"),
            SignatureEnforcementMode.Strict);

        Assert.Equal(ServiceStartupDecision.Allow, decision.Decision);
        Assert.Equal(ServiceSignatureGuard.InfoLevel, decision.Level);
        Assert.Contains("签名校验通过", decision.Message);
    }

    [Fact]
    public void StrictMode_AllowsSignatureWithoutPublisherPinningButWarns()
    {
        var decision = ServiceSignatureGuard.Evaluate(
            Check(AuthenticodeStatus.Valid, PublisherTrust.NotConfigured, "CN=FolderLock"),
            SignatureEnforcementMode.Strict);

        Assert.Equal(ServiceStartupDecision.Allow, decision.Decision);
        Assert.Equal(ServiceSignatureGuard.WarningLevel, decision.Level);
        Assert.Contains("发布者固定校验未生效", decision.Message);
    }

    [Theory]
    [InlineData(SignatureEnforcementMode.Warn, "警告（不强制签名，仅记录校验结果）")]
    [InlineData(SignatureEnforcementMode.Strict, "严格（未签名或签名无效即拒绝启动）")]
    public void EveryDecisionStatesCurrentMode(SignatureEnforcementMode mode, string expected)
    {
        var decision = ServiceSignatureGuard.Evaluate(Check(AuthenticodeStatus.NotSigned), mode);

        Assert.Contains("当前模式：", decision.Message);
        Assert.Contains(expected, decision.Message);
    }
}
