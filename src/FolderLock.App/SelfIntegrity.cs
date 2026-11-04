using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using FolderLock.Core.Security;

namespace FolderLock.App;

public static class SelfIntegrity
{
    /// <summary>
    /// 优先用 Authenticode 签名判断完整性；签名有效但发布者不符时直接判定被替换；
    /// 未签名（开发版/便携版）时退化为发布时记录的哈希比对。
    /// </summary>
    public static bool Ensure()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
            {
                return true;
            }

            var check = AuthenticodePolicy.Check(exe);
            if (check.IsTrusted)
            {
                if (check.Publisher == PublisherTrust.NotConfigured)
                {
                    Debug.WriteLine(check.Message);
                }

                return true;
            }

            // 签名有效但签名者不是预期发布者：视为被重新打包，不再退化为哈希比对。
            if (check.Status == AuthenticodeStatus.Valid)
            {
                Debug.WriteLine(check.Message);
                return false;
            }

            var hash = ComputeHash(exe);
            var settings = AppSettings.Current;
            if (string.IsNullOrEmpty(settings.ExecutableHash))
            {
                settings.ExecutableHash = hash;
                settings.Save();
                return true;
            }

            return string.Equals(settings.ExecutableHash, hash, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return true;
        }
    }

    /// <summary>更新成功替换可执行文件后调用，刷新记录的哈希，避免下次启动误报“文件被修改”。</summary>
    public static void Refresh()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
            {
                return;
            }

            var settings = AppSettings.Current;
            settings.ExecutableHash = ComputeHash(exe);
            settings.Save();
        }
        catch
        {
        }
    }

    private static string ComputeHash(string exe)
    {
        using var stream = File.OpenRead(exe);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
