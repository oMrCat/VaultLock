using FolderLock.Core.Data;

namespace FolderLock.Core.Security;

public enum PublisherTrust
{
    /// <summary>未配置预期发布者，只校验“签名有效”。</summary>
    NotConfigured,

    /// <summary>签名有效，且签名者主题与预期发布者一致。</summary>
    Matched,

    /// <summary>签名有效，但签名者主题与预期发布者不一致。</summary>
    Mismatched,
}

public sealed record AuthenticodeCheck(
    AuthenticodeStatus Status,
    string? SignerSubject,
    PublisherTrust Publisher,
    string? Message)
{
    /// <summary>
    /// 可信 = 签名有效，且没有命中“发布者不匹配”。
    /// 未配置预期发布者时按旧行为放行，但调用方应记录 <see cref="Message"/> 中的警告。
    /// </summary>
    public bool IsTrusted => Status == AuthenticodeStatus.Valid && Publisher != PublisherTrust.Mismatched;
}

/// <summary>
/// Authenticode 校验策略：在“签名有效”之上再固定发布者主题，
/// 防止任何有效证书（包括攻击者自购证书）签出的恶意 exe 通过校验。
/// 预期值来源（按优先级）：环境变量 <c>FOLDERLOCK_EXPECTED_PUBLISHERS</c>（分号分隔）
/// → 数据目录下 <c>expected-publishers.txt</c> → <c>%ProgramData%\FolderLock\expected-publishers.txt</c>。
/// </summary>
public static class AuthenticodePolicy
{
    public const string PublisherEnvironmentVariable = "FOLDERLOCK_EXPECTED_PUBLISHERS";

    public const string PublisherFileName = "expected-publishers.txt";

    public static AuthenticodeCheck Check(string path)
    {
        var status = Authenticode.GetStatus(path);
        if (status != AuthenticodeStatus.Valid)
        {
            return new AuthenticodeCheck(
                status,
                null,
                PublisherTrust.NotConfigured,
                $"Authenticode 状态为 {status}，未通过签名校验。");
        }

        var subject = Authenticode.GetSignerSubject(path);
        if (subject is null)
        {
            return new AuthenticodeCheck(
                status,
                null,
                PublisherTrust.NotConfigured,
                "签名有效，但无法读取签名者证书主题，发布者固定校验已跳过。");
        }

        var expected = LoadExpectedPublishers();
        if (expected.Count == 0)
        {
            return new AuthenticodeCheck(
                status,
                subject,
                PublisherTrust.NotConfigured,
                $"签名有效（签名者：{subject}），但未配置预期发布者（环境变量 {PublisherEnvironmentVariable} 或 {PublisherFileName}），仅校验了签名有效性。");
        }

        if (Matches(subject, expected))
        {
            return new AuthenticodeCheck(
                status,
                subject,
                PublisherTrust.Matched,
                $"签名有效且发布者匹配：{subject}");
        }

        return new AuthenticodeCheck(
            status,
            subject,
            PublisherTrust.Mismatched,
            $"签名有效，但签名者“{subject}”不在预期发布者列表中（{string.Join(" | ", expected)}）。");
    }

    public static IReadOnlyList<string> LoadExpectedPublishers()
    {
        var fromEnvironment = Environment.GetEnvironmentVariable(PublisherEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            return Split(fromEnvironment);
        }

        foreach (var candidate in ConfigFileCandidates())
        {
            try
            {
                if (File.Exists(candidate))
                {
                    return Split(File.ReadAllText(candidate));
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return Array.Empty<string>();
    }

    /// <summary>比较签名者主题；忽略大小写与空白差异，其余按 DN 原文比较。</summary>
    public static bool Matches(string? subject, IEnumerable<string> expected)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return false;
        }

        var normalized = Normalize(subject);
        return expected.Any(item => string.Equals(Normalize(item), normalized, StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> ConfigFileCandidates()
    {
        yield return Path.Combine(AppPaths.DataDirectory, PublisherFileName);

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrEmpty(programData))
        {
            yield return Path.Combine(programData, "FolderLock", PublisherFileName);
        }
    }

    private static List<string> Split(string value)
    {
        return value
            .Split([';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => item.Length > 0 && !item.StartsWith('#'))
            .ToList();
    }

    private static string Normalize(string value)
    {
        return string.Concat(value.Where(character => !char.IsWhiteSpace(character)));
    }
}
