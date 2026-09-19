using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FolderLock.Core.Security;

public sealed class RecoveryKitEntry
{
    public string Path { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string? PasswordHash { get; set; }

    public string? RecoveryHash { get; set; }

    public string? RecoveryCode { get; set; }

    public int EncryptionMode { get; set; }

    public bool IsLocked { get; set; }

    public string? DaclSddl { get; set; }

    public bool AccessRulesProtected { get; set; }

    public string? VaultPath { get; set; }
}

public static class RecoveryKit
{
    public const string Extension = ".flkit";

    private const string Magic = "FLKIT1";
    private const byte Version = 1;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    public static void Export(
        string kitPath,
        ReadOnlySpan<char> passphrase,
        IReadOnlyList<RecoveryKitEntry> entries,
        int iterations = PasswordHasher.DefaultIterations)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kitPath);
        ArgumentNullException.ThrowIfNull(entries);
        if (passphrase.IsEmpty)
        {
            throw new ArgumentException("Passphrase must not be empty.", nameof(passphrase));
        }

        var json = JsonSerializer.SerializeToUtf8Bytes(entries);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = PasswordHasher.Derive(passphrase, salt, iterations, KeySize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var cipher = new byte[json.Length];
        var tag = new byte[TagSize];

        try
        {
            using (var gcm = new AesGcm(key, TagSize))
            {
                gcm.Encrypt(nonce, json, cipher, tag);
            }

            var directory = Path.GetDirectoryName(Path.GetFullPath(kitPath));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var fs = new FileStream(kitPath, FileMode.Create, FileAccess.Write, FileShare.None);
            fs.Write(Encoding.ASCII.GetBytes(Magic));
            fs.WriteByte(Version);
            Span<byte> intBuffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(intBuffer, iterations);
            fs.Write(intBuffer);
            fs.Write(salt);
            fs.Write(nonce);
            fs.Write(tag);
            fs.Write(cipher);
            fs.Flush(flushToDisk: true);
        }
        finally
        {
            Array.Clear(key);
            Array.Clear(json);
        }
    }

    public static IReadOnlyList<RecoveryKitEntry> Import(string kitPath, ReadOnlySpan<char> passphrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kitPath);
        if (passphrase.IsEmpty)
        {
            throw new ArgumentException("Passphrase must not be empty.", nameof(passphrase));
        }

        using var fs = new FileStream(kitPath, FileMode.Open, FileAccess.Read, FileShare.Read);

        var magic = new byte[6];
        fs.ReadExactly(magic);
        if (!Encoding.ASCII.GetBytes(Magic).AsSpan().SequenceEqual(magic))
        {
            throw new VaultException("不是有效的恢复套件文件。");
        }

        var version = fs.ReadByte();
        if (version != Version)
        {
            throw new VaultException($"不支持的套件版本：{version}");
        }

        var intBuffer = new byte[4];
        fs.ReadExactly(intBuffer);
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(intBuffer);
        if (iterations <= 0)
        {
            throw new VaultException("套件 KDF 参数无效。");
        }

        var salt = new byte[SaltSize];
        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        fs.ReadExactly(salt);
        fs.ReadExactly(nonce);
        fs.ReadExactly(tag);

        var cipher = new byte[fs.Length - fs.Position];
        fs.ReadExactly(cipher);

        var key = PasswordHasher.Derive(passphrase, salt, iterations, KeySize);
        var plain = new byte[cipher.Length];
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            gcm.Decrypt(nonce, cipher, tag, plain);
        }
        catch (CryptographicException)
        {
            throw new VaultException("口令不正确或恢复套件已损坏。");
        }
        finally
        {
            Array.Clear(key);
        }

        return JsonSerializer.Deserialize<List<RecoveryKitEntry>>(plain) ?? new List<RecoveryKitEntry>();
    }
}
