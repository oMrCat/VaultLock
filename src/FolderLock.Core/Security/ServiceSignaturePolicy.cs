using System.Text.Json;
using FolderLock.Core.Data;

namespace FolderLock.Core.Security;

/// <summary>守护服务启动时签名校验的强制级别。</summary>
public enum SignatureEnforcementMode
{
    /// <summary>警告模式（默认）：仍然校验签名，但结果只落日志，不阻止启动。</summary>
    Warn,

    /// <summary>严格模式：未签名、签名无效或发布者不符时拒绝启动。</summary>
    Strict,
}

/// <summary>服务签名校验配置文件的模型。</summary>
public sealed class ServiceSignatureSettings
{
    /// <summary>是否强制要求服务可执行文件具备受信任签名；默认 false。</summary>
    public bool RequireServiceSignature { get; set; }
}

/// <summary>
/// 服务签名校验配置：默认警告模式（<c>RequireServiceSignature = false</c>），
/// 环境变量 <c>FOLDERLOCK_REQUIRE_SIGNATURE</c> 可覆盖配置文件
/// （<c>1/true/yes/on</c> 为严格模式，其余值为警告模式）。
/// 配置文件为数据目录下的 <c>service-settings.json</c>；正式安装时为
/// <c>%ProgramData%\FolderLock\service-settings.json</c>。
/// </summary>
public static class ServiceSignaturePolicy
{
    public const string RequireEnvironmentVariable = "FOLDERLOCK_REQUIRE_SIGNATURE";

    public const string SettingsFileName = "service-settings.json";

    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    /// <summary>当前是否要求强制签名。<paramref name="settingsPath"/> 仅用于测试注入。</summary>
    public static bool IsRequired(string? settingsPath = null)
    {
        var fromEnvironment = Environment.GetEnvironmentVariable(RequireEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            return IsTruthy(fromEnvironment);
        }

        var path = settingsPath ?? GetDefaultSettingsPath();
        try
        {
            if (File.Exists(path))
            {
                var settings = JsonSerializer.Deserialize<ServiceSignatureSettings>(File.ReadAllText(path), Options);
                if (settings is not null)
                {
                    return settings.RequireServiceSignature;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
        }

        return false;
    }

    public static SignatureEnforcementMode CurrentMode =>
        IsRequired() ? SignatureEnforcementMode.Strict : SignatureEnforcementMode.Warn;

    public static string GetDefaultSettingsPath()
    {
        if (AppPaths.IsPortable)
        {
            return Path.Combine(AppPaths.DataDirectory, SettingsFileName);
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "FolderLock",
            SettingsFileName);
    }

    public static string Describe(SignatureEnforcementMode mode) => mode == SignatureEnforcementMode.Strict
        ? "严格（未签名或签名无效即拒绝启动）"
        : "警告（不强制签名，仅记录校验结果）";

    private static bool IsTruthy(string value)
    {
        return value.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
    }
}
