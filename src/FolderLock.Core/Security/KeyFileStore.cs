using System.Security.Cryptography;
using FolderLock.Core.Util;

namespace FolderLock.Core.Security;

/// <summary>本地数据库密钥文件损坏（非 Base64 / DPAPI 解密失败 / 长度异常）。</summary>
public sealed class KeyFileException : Exception
{
    public KeyFileException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

/// <summary>
/// 数据库密钥的读取与首次创建。核心约束：密钥文件已存在但损坏时绝不重新生成，
/// 否则已加密的数据库将永久无法打开；创建时原子写并保留一份 .bak 冗余副本。
/// </summary>
public static class KeyFileStore
{
    public static byte[] GetOrCreate(
        string path,
        Func<byte[], byte[]> protect,
        Func<byte[], byte[]> unprotect,
        int minLength = 32)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(protect);
        ArgumentNullException.ThrowIfNull(unprotect);

        if (!File.Exists(path))
        {
            return CreateAndStore(path, protect, minLength);
        }

        byte[] protectedBytes;
        try
        {
            protectedBytes = Convert.FromBase64String(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            throw new KeyFileException(
                $"数据库密钥文件已损坏（不是有效的 Base64）：{path}。可尝试从同名 .bak 文件恢复，程序不会自动重建密钥。",
                ex);
        }

        byte[] key;
        try
        {
            key = unprotect(protectedBytes);
        }
        catch (Exception ex)
        {
            throw new KeyFileException(
                $"无法用当前 Windows 账户解密数据库密钥：{path}。" +
                "通常是与创建密钥时的用户/机器不同；可尝试从 .bak 恢复或使用原账户登录，程序不会自动重建密钥。",
                ex);
        }

        if (key.Length < minLength)
        {
            throw new KeyFileException(
                $"数据库密钥长度异常（{key.Length} 字节，至少需要 {minLength}）：{path}。程序不会自动重建密钥。");
        }

        return key;
    }

    private static byte[] CreateAndStore(string path, Func<byte[], byte[]> protect, int minLength)
    {
        var newKey = RandomNumberGenerator.GetBytes(Math.Max(minLength, 32));

        string encoded;
        try
        {
            encoded = Convert.ToBase64String(protect(newKey));
        }
        catch (Exception ex)
        {
            throw new KeyFileException($"无法用 DPAPI 保护新生成的数据库密钥：{path}", ex);
        }

        try
        {
            AtomicFile.WriteAllText(path, encoded);
        }
        catch (Exception ex)
        {
            throw new KeyFileException($"无法写入数据库密钥文件：{path}", ex);
        }

        // 冗余副本，便于主文件损坏时人工恢复；写入失败不影响主密钥可用性。
        try
        {
            AtomicFile.WriteAllText(path + ".bak", encoded);
        }
        catch
        {
        }

        return newKey;
    }
}
