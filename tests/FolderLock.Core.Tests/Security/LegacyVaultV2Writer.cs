using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

/// <summary>
/// 测试专用：按 v2 旧格式生成容器，用于验证 v1/v2 只读兼容与 v2 → v3 升级。
/// </summary>
internal static class LegacyVaultV2Writer
{
    private const int ChunkSize = 64 * 1024;
    private const int TagSize = 16;
    private const int NonceSize = 12;

    public static void Write(
        string sourceDirectory,
        string vaultPath,
        string password,
        string? recoveryCode,
        int iterations = 1000,
        bool compressed = false)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sourceDirectory));
        var dek = RandomNumberGenerator.GetBytes(32);
        var saltPassword = RandomNumberGenerator.GetBytes(16);
        var saltRecovery = RandomNumberGenerator.GetBytes(16);

        var kekPassword = Rfc2898DeriveBytes.Pbkdf2(
            password,
            saltPassword,
            iterations,
            HashAlgorithmName.SHA256,
            32);
        var wrappedPassword = Wrap(kekPassword, dek);
        var hasRecovery = !string.IsNullOrWhiteSpace(recoveryCode);
        var wrappedRecovery = new byte[60];
        if (hasRecovery)
        {
            var kekRecovery = Rfc2898DeriveBytes.Pbkdf2(
                RecoveryCode.Normalize(recoveryCode!),
                saltRecovery,
                iterations,
                HashAlgorithmName.SHA256,
                32);
            wrappedRecovery = Wrap(kekRecovery, dek);
        }

        var prefix = new byte[164];
        Encoding.ASCII.GetBytes("FLVLT1").CopyTo(prefix, 0);
        prefix[6] = 2;
        prefix[7] = (byte)((hasRecovery ? 1 : 0) | (compressed ? 2 : 0));
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(8, 4), iterations);
        saltPassword.CopyTo(prefix, 12);
        saltRecovery.CopyTo(prefix, 28);
        wrappedPassword.CopyTo(prefix, 44);
        wrappedRecovery.CopyTo(prefix, 104);

        using var hmac = new HMACSHA256(dek);
        var mac = hmac.ComputeHash(prefix);

        var payload = new MemoryStream();
        WriteManifest(root, payload);
        var payloadBytes = compressed
            ? Compress(payload.ToArray())
            : payload.ToArray();

        using var output = new FileStream(vaultPath, FileMode.Create, FileAccess.Write, FileShare.None);
        output.Write(prefix);
        output.Write(mac);

        using var gcm = new AesGcm(dek, TagSize);
        long index = 0;
        long total = 0;
        var position = 0;
        while (position < payloadBytes.Length)
        {
            var length = Math.Min(ChunkSize, payloadBytes.Length - position);
            var chunk = payloadBytes.AsSpan(position, length).ToArray();
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[length];
            var tag = new byte[TagSize];
            gcm.Encrypt(nonce, chunk, ciphertext, tag, CreateAad(index));

            var lengthBytes = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, length);
            output.Write(lengthBytes);
            output.Write(nonce);
            output.Write(ciphertext);
            output.Write(tag);

            index++;
            total += length;
            position += length;
        }

        var manifest = new byte[16];
        BinaryPrimitives.WriteInt64LittleEndian(manifest.AsSpan(0, 8), index);
        BinaryPrimitives.WriteInt64LittleEndian(manifest.AsSpan(8, 8), total);
        var trailerNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var trailerCipher = new byte[16];
        var trailerTag = new byte[TagSize];
        gcm.Encrypt(trailerNonce, manifest, trailerCipher, trailerTag, CreateAad(index));

        var marker = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(marker, -1);
        output.Write(marker);
        output.Write(trailerNonce);
        output.Write(trailerCipher);
        output.Write(trailerTag);
    }

    private static void WriteManifest(string root, Stream payload)
    {
        var entries = new List<(bool IsDirectory, string Relative, long Ticks, string? FullPath)>();
        Collect(root, root, entries);

        using var binary = new BinaryWriter(payload, Encoding.UTF8, leaveOpen: true);
        binary.Write(entries.Count);
        foreach (var entry in entries)
        {
            binary.Write((byte)(entry.IsDirectory ? 1 : 0));
            var relativeBytes = Encoding.UTF8.GetBytes(entry.Relative);
            binary.Write(relativeBytes.Length);
            binary.Write(relativeBytes);
            binary.Write(entry.Ticks);
            if (!entry.IsDirectory)
            {
                binary.Write(new FileInfo(entry.FullPath!).Length);
                binary.Write(File.ReadAllBytes(entry.FullPath!));
            }
        }
    }

    private static void Collect(
        string root,
        string directory,
        List<(bool, string, long, string?)> entries)
    {
        foreach (var subdirectory in Directory.GetDirectories(directory).OrderBy(path => path))
        {
            var relative = Path.GetRelativePath(root, subdirectory).Replace('\\', '/');
            entries.Add((true, relative, Directory.GetLastWriteTimeUtc(subdirectory).Ticks, null));
            Collect(root, subdirectory, entries);
        }

        foreach (var file in Directory.GetFiles(directory).OrderBy(path => path))
        {
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            entries.Add((false, relative, File.GetLastWriteTimeUtc(file).Ticks, file));
        }
    }

    private static byte[] Wrap(byte[] kek, byte[] dek)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[32];
        var tag = new byte[TagSize];
        using var gcm = new AesGcm(kek, TagSize);
        gcm.Encrypt(nonce, dek, ciphertext, tag);

        var wrapped = new byte[60];
        nonce.CopyTo(wrapped, 0);
        ciphertext.CopyTo(wrapped, 12);
        tag.CopyTo(wrapped, 44);
        return wrapped;
    }

    private static byte[] CreateAad(long index)
    {
        var aad = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(aad, index);
        return aad;
    }

    private static byte[] Compress(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(
                   output,
                   System.IO.Compression.CompressionMode.Compress,
                   leaveOpen: true))
        {
            gzip.Write(data);
        }

        return output.ToArray();
    }
}
