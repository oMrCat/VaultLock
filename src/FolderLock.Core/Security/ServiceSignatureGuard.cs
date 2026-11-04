namespace FolderLock.Core.Security;

public enum ServiceStartupDecision
{
    /// <summary>允许启动（校验失败时仅记录警告）。</summary>
    Allow,

    /// <summary>拒绝启动（严格模式下校验未通过）。</summary>
    Refuse,
}

/// <summary>一次启动判定的结论：模式、是否放行、日志级别与可读说明。</summary>
public sealed record ServiceSignatureDecision(
    SignatureEnforcementMode Mode,
    ServiceStartupDecision Decision,
    string Level,
    string Message)
{
    public bool IsRefused => Decision == ServiceStartupDecision.Refuse;
}

/// <summary>
/// 把 <see cref="AuthenticodeCheck"/> 的结果按强制级别翻译成启动决定。
/// 纯函数，便于对每个分支做单元测试（不依赖真实签名文件）。
/// </summary>
public static class ServiceSignatureGuard
{
    public const string InfoLevel = "信息";

    public const string WarningLevel = "警告";

    public const string ErrorLevel = "错误";

    public static ServiceSignatureDecision Evaluate(AuthenticodeCheck check, SignatureEnforcementMode mode)
    {
        ArgumentNullException.ThrowIfNull(check);

        var modeText = $"当前模式：{ServiceSignaturePolicy.Describe(mode)}。";

        if (mode == SignatureEnforcementMode.Strict)
        {
            if (!check.IsTrusted)
            {
                return new ServiceSignatureDecision(
                    mode,
                    ServiceStartupDecision.Refuse,
                    ErrorLevel,
                    $"{modeText}拒绝启动：签名校验未通过。{check.Message}" +
                    "发布的服务可执行文件必须使用受信任证书签名，且签名者必须是预期发布者。");
            }

            return new ServiceSignatureDecision(
                mode,
                ServiceStartupDecision.Allow,
                check.Publisher == PublisherTrust.NotConfigured ? WarningLevel : InfoLevel,
                check.Publisher == PublisherTrust.NotConfigured
                    ? $"{modeText}发布者固定校验未生效。{check.Message}"
                    : $"{modeText}签名校验通过（签名者：{check.SignerSubject}）。");
        }

        if (!check.IsTrusted)
        {
            return new ServiceSignatureDecision(
                mode,
                ServiceStartupDecision.Allow,
                WarningLevel,
                $"{modeText}签名校验未通过，按警告模式继续启动。{check.Message}");
        }

        return new ServiceSignatureDecision(
            mode,
            ServiceStartupDecision.Allow,
            check.Publisher == PublisherTrust.NotConfigured ? WarningLevel : InfoLevel,
            check.Publisher == PublisherTrust.NotConfigured
                ? $"{modeText}发布者固定校验未生效。{check.Message}"
                : $"{modeText}签名校验通过（签名者：{check.SignerSubject}）。");
    }
}
