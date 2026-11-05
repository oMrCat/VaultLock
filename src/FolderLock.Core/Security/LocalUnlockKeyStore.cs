using System.Security.Cryptography;
using System.Text;
using FolderLock.Core.Data;

namespace FolderLock.Core.Security;

/// <summary>
/// DPAPI（CurrentUser）保护的本机自动解锁 KEK。
/// 密钥本体只存 SQLCipher 数据库，不进入容器头部；任何能读取当前用户 DPAPI 私钥的进程都能解封。
/// </summary>
public sealed class LocalUnlockKeyStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("VaultLock.LocalUnlockKey.v1");

    private readonly FolderStore _store;

    public LocalUnlockKeyStore(FolderStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>读取已有的机器密钥；不存在或当前用户无法解封时返回 null。</summary>
    public byte[]? TryGet(long folderId)
    {
        var protectedKey = _store.GetLocalUnlockKey(folderId);
        if (string.IsNullOrWhiteSpace(protectedKey))
        {
            return null;
        }

        try
        {
            var raw = Convert.FromBase64String(protectedKey);
            var key = ProtectedData.Unprotect(raw, Entropy, DataProtectionScope.CurrentUser);
            return key.Length == VaultKeySlot.KeySize ? key : null;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return null;
        }
    }

    /// <summary>读取或创建机器密钥并落库。已有数据损坏时会替换为新密钥。</summary>
    public byte[] GetOrCreate(long folderId)
    {
        var existing = TryGet(folderId);
        if (existing is not null)
        {
            return existing;
        }

        var key = RandomNumberGenerator.GetBytes(VaultKeySlot.KeySize);
        _store.SaveLocalUnlockKey(folderId, Protect(key));
        return key;
    }

    public void Remove(long folderId) => _store.DeleteLocalUnlockKey(folderId);

    private static string Protect(byte[] key)
    {
        var protectedBytes = ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(protectedBytes);
    }
}
