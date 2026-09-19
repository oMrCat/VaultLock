using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;

namespace FolderLock.Core.Update;

public sealed class UpdateManifest
{
    public string Version { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public string Sha256 { get; set; } = string.Empty;

    public string? Notes { get; set; }
}

public static class Updater
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public static bool IsNewer(string currentVersion, string candidateVersion)
    {
        return Version.TryParse(candidateVersion, out var candidate)
               && Version.TryParse(currentVersion, out var current)
               && candidate > current;
    }

    public static async Task<UpdateManifest?> CheckAsync(
        string manifestUrl,
        string currentVersion,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(manifestUrl))
        {
            return null;
        }

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var json = await http.GetStringAsync(manifestUrl, cancellationToken);
        var manifest = JsonSerializer.Deserialize<UpdateManifest>(json, Options);

        if (manifest is null ||
            string.IsNullOrWhiteSpace(manifest.Version) ||
            string.IsNullOrWhiteSpace(manifest.Url))
        {
            return null;
        }

        return IsNewer(currentVersion, manifest.Version) ? manifest : null;
    }

    public static string VerifyHash(byte[] content, string expectedSha256)
    {
        var actual = Convert.ToHexString(SHA256.HashData(content));
        if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("更新包校验失败（哈希不匹配）。");
        }

        return actual;
    }

    public static async Task<string> DownloadAsync(
        UpdateManifest manifest,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        var content = await http.GetByteArrayAsync(manifest.Url, cancellationToken);

        if (!string.IsNullOrWhiteSpace(manifest.Sha256))
        {
            VerifyHash(content, manifest.Sha256);
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(destinationPath));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllBytesAsync(destinationPath, content, cancellationToken);
        return destinationPath;
    }
}
