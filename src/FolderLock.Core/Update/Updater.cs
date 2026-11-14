using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FolderLock.Core.Data;
using FolderLock.Core.Security;

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
    /// <summary>更新包大小上限：256 MB。</summary>
    public const long MaxPackageBytes = 256L * 1024 * 1024;

    /// <summary>
    /// 默认更新清单地址（GitHub Releases 的 latest/download 直链，302 到 HTTPS CDN，
    /// 不经过 api.github.com，不受匿名限速影响）。清单格式见 <see cref="UpdateManifest"/>。
    /// </summary>
    public const string DefaultManifestUrl =
        "https://github.com/oMrCat/VaultLock/releases/latest/download/latest.json";

    /// <summary>
    /// 解析实际使用的清单地址：用户配置为空/空白时回落默认源。
    /// 必须在调用点回落而非仅改设置默认值——老用户 settings.json 里已序列化的
    /// 空字符串会在反序列化时覆盖属性默认值。
    /// </summary>
    public static string ResolveManifestUrl(string? configured)
    {
        return string.IsNullOrWhiteSpace(configured) ? DefaultManifestUrl : configured;
    }

    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public static bool IsNewer(string currentVersion, string candidateVersion)
    {
        return Version.TryParse(candidateVersion, out var candidate)
               && Version.TryParse(currentVersion, out var current)
               && candidate > current;
    }

    /// <summary>校验更新清单的安全约束；返回 null 表示通过，否则返回错误说明。</summary>
    public static string? ValidateManifest(UpdateManifest? manifest)
    {
        if (manifest is null)
        {
            return "更新清单为空。";
        }

        if (string.IsNullOrWhiteSpace(manifest.Version))
        {
            return "更新清单缺少版本号。";
        }

        if (!IsHttpsUrl(manifest.Url))
        {
            return "更新包地址必须使用 HTTPS。";
        }

        if (!IsSha256Hex(manifest.Sha256))
        {
            return "更新清单必须提供有效的 SHA-256（64 位十六进制）。";
        }

        return null;
    }

    public static bool IsHttpsUrl(string? url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
               string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSha256Hex(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) &&
               value.Length == 64 &&
               value.All(Uri.IsHexDigit);
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

        if (!IsHttpsUrl(manifestUrl))
        {
            throw new InvalidOperationException("更新清单地址必须使用 HTTPS。");
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

        var error = ValidateManifest(manifest);
        if (error is not null)
        {
            throw new InvalidOperationException(error);
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

    /// <summary>
    /// 下载更新包：仅 HTTPS、强制哈希、大小上限、流式分块写临时文件并在落盘前完成哈希与签名校验，
    /// 任何失败都不会留下半截目标文件。
    /// </summary>
    public static async Task<string> DownloadAsync(
        UpdateManifest manifest,
        string destinationPath,
        bool requireSignature = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);

        var validation = ValidateManifest(manifest);
        if (validation is not null)
        {
            throw new InvalidOperationException(validation);
        }

        var target = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(target);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temp = target + ".part-" + Guid.NewGuid().ToString("N");

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
            using var response = await http.SendAsync(
                new HttpRequestMessage(HttpMethod.Get, manifest.Url),
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            response.EnsureSuccessStatusCode();

            var finalUri = response.RequestMessage?.RequestUri;
            if (finalUri is null || !IsHttpsUrl(finalUri.AbsoluteUri))
            {
                throw new InvalidOperationException("更新下载被重定向到非 HTTPS 地址，已中止。");
            }

            if (response.Content.Headers.ContentLength is { } declared && declared > MaxPackageBytes)
            {
                throw new InvalidOperationException($"更新包过大（{declared} 字节），超过上限 {MaxPackageBytes} 字节。");
            }

            var expectedHash = Convert.FromHexString(manifest.Sha256);
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[81920];
            long total = 0;

            await using (var source = await response.Content.ReadAsStreamAsync(cancellationToken))
            await using (var file = new FileStream(
                             temp,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             buffer.Length,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                int read;
                while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
                {
                    total += read;
                    if (total > MaxPackageBytes)
                    {
                        throw new InvalidOperationException($"更新包超过大小上限 {MaxPackageBytes} 字节，已中止。");
                    }

                    hasher.AppendData(buffer, 0, read);
                    await file.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }

                await file.FlushAsync(cancellationToken);
            }

            var actualHash = hasher.GetHashAndReset();
            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
            {
                throw new InvalidOperationException(
                    $"更新包校验失败（哈希不匹配）：期望 {manifest.Sha256}，实际 {Convert.ToHexString(actualHash)}。");
            }

            if (requireSignature)
            {
                var check = AuthenticodePolicy.Check(temp);
                if (!check.IsTrusted)
                {
                    throw new InvalidOperationException($"更新包签名校验未通过，已拒绝更新。{check.Message}");
                }
            }

            File.Move(temp, target, overwrite: true);
            return target;
        }
        finally
        {
            TryDelete(temp);
        }
    }

    /// <summary>
    /// 覆盖当前程序前的校验：文件必须存在、非空、是有效的 Windows 可执行文件、哈希与清单一致，
    /// 且默认要求有效的 Authenticode 签名。校验失败抛出 <see cref="InvalidOperationException"/>。
    /// </summary>
    public static string VerifyStagedFile(
        string stagedPath,
        string? expectedSha256,
        bool requireSignature = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stagedPath);

        if (!IsSha256Hex(expectedSha256))
        {
            throw new InvalidOperationException("更新校验缺少有效的 SHA-256，已中止更新。");
        }

        var file = new FileInfo(stagedPath);
        if (!file.Exists)
        {
            throw new InvalidOperationException($"更新文件不存在：{stagedPath}");
        }

        if (file.Length < 64)
        {
            throw new InvalidOperationException($"更新文件异常（仅 {file.Length} 字节），已中止更新。");
        }

        using (var stream = file.OpenRead())
        {
            Span<byte> signature = stackalloc byte[2];
            stream.ReadExactly(signature);
            if (signature[0] != (byte)'M' || signature[1] != (byte)'Z')
            {
                throw new InvalidOperationException("更新文件不是有效的 Windows 可执行文件（缺少 MZ 头），已中止更新。");
            }
        }

        string hash;
        using (var stream = file.OpenRead())
        {
            hash = Convert.ToHexString(SHA256.HashData(stream));
        }

        if (!string.Equals(hash, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"更新文件校验失败（哈希不匹配）：期望 {expectedSha256}，实际 {hash}。已中止更新。");
        }

        if (requireSignature)
        {
            var check = AuthenticodePolicy.Check(stagedPath);
            if (!check.IsTrusted)
            {
                throw new InvalidOperationException($"更新文件签名校验未通过，已中止更新。{check.Message}");
            }
        }

        return hash;
    }

    public static string GetApplyResultPath()
    {
        return Path.Combine(AppPaths.DataDirectory, "update-result.txt");
    }

    /// <summary>读取并删除上一次替换进程写入的结果，没有结果时返回 null。</summary>
    public static string? ConsumeApplyResult()
    {
        var path = GetApplyResultPath();
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var text = File.ReadAllText(path).Trim();
            File.Delete(path);
            return text;
        }
        catch
        {
            return null;
        }
    }

    public static string WriteApplyScript(
        string newExecutable,
        string currentExecutable,
        string resultPath,
        int processId)
    {
        var script = Path.Combine(Path.GetTempPath(), $"folderlock-update-{Guid.NewGuid():N}.cmd");
        File.WriteAllText(
            script,
            BuildApplyScript(newExecutable, currentExecutable, resultPath, processId),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return script;
    }

    /// <summary>
    /// 生成在旧进程退出后执行替换的批处理：
    /// 等待旧进程真正结束（而不是固定 sleep）、带重试地复制、检查 errorlevel，
    /// 成功/失败都写入结果文件，失败时重启旧版本并把原因留给下次启动提示。
    /// </summary>
    public static string BuildApplyScript(
        string newExecutable,
        string currentExecutable,
        string resultPath,
        int processId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newExecutable);
        ArgumentException.ThrowIfNullOrWhiteSpace(currentExecutable);
        ArgumentException.ThrowIfNullOrWhiteSpace(resultPath);

        var content =
            "@echo off\r\n" +
            "setlocal\r\n" +
            $"set \"NEW={newExecutable}\"\r\n" +
            $"set \"CUR={currentExecutable}\"\r\n" +
            $"set \"RESULT={resultPath}\"\r\n" +
            "set WAIT=0\r\n" +
            ":wait\r\n" +
            $"powershell -NoProfile -Command \"if (-not (Get-Process -Id {processId} -ErrorAction SilentlyContinue)) {{ exit 0 }}; exit 1\"\r\n" +
            "if not errorlevel 1 goto copy\r\n" +
            "set /a WAIT+=1\r\n" +
            "if %WAIT% GEQ 30 goto wait_failed\r\n" +
            "timeout /t 1 /nobreak >nul\r\n" +
            "goto wait\r\n" +
            ":copy\r\n" +
            "set ATTEMPTS=0\r\n" +
            ":copy_retry\r\n" +
            "copy /y \"%NEW%\" \"%CUR%\" >nul 2>&1\r\n" +
            "if not errorlevel 1 goto copy_ok\r\n" +
            "set /a ATTEMPTS+=1\r\n" +
            "if %ATTEMPTS% GEQ 5 goto copy_failed\r\n" +
            "timeout /t 2 /nobreak >nul\r\n" +
            "goto copy_retry\r\n" +
            ":copy_ok\r\n" +
            "> \"%RESULT%\" echo ok\r\n" +
            "del \"%NEW%\" >nul 2>&1\r\n" +
            "start \"\" \"%CUR%\"\r\n" +
            "goto cleanup\r\n" +
            ":copy_failed\r\n" +
            "> \"%RESULT%\" echo failed\r\n" +
            ">> \"%RESULT%\" echo copy failed after 5 attempts\r\n" +
            "start \"\" \"%CUR%\"\r\n" +
            "goto cleanup\r\n" +
            ":wait_failed\r\n" +
            "> \"%RESULT%\" echo failed\r\n" +
            ">> \"%RESULT%\" echo timed out waiting for the old process to exit\r\n" +
            "start \"\" \"%CUR%\"\r\n" +
            ":cleanup\r\n" +
            "del \"%~f0\" >nul 2>&1\r\n" +
            "exit /b 0\r\n";

        return content;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }
}
