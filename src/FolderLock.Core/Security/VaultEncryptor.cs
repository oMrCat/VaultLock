using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace FolderLock.Core.Security;

public sealed class VaultException : Exception
{
    public VaultException(string message)
        : base(message)
    {
    }

    public VaultException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

public readonly record struct VaultProgress(long Processed, long Total)
{
    public double Percent => Total <= 0 ? 0 : Math.Clamp((double)Processed / Total * 100.0, 0, 100);
}

public readonly record struct VaultHeaderInfo(int Version, bool HasRecovery, bool IsCompressed, int Iterations, long Size);

public readonly record struct SalvageResult(bool Success, string? Error);

/// <summary>加密结果中的附加信息：哪些条目因是符号链接/目录联接而没有进入容器。</summary>
public sealed class VaultEncryptionReport
{
    public List<string> SkippedEntries { get; } = new();
}

/// <summary>
/// 加密容器（.flvault）读写实现。
///
/// 格式 v2：
///   [6 字节魔数][1 版本][1 flags][4 迭代次数][16 盐 A][16 盐 B][60 包装密钥 A][60 包装密钥 B][32 头部 HMAC]
///   [数据块 ...]（每块：4 长度 + 12 nonce + N 密文 + 16 认证标签，AAD = 块序号）
///   [结束块：4 长度(= -1) + 12 nonce + 16 密文 + 16 标签，明文为 (块数, 明文总字节数)]
///
/// 加密算法：AES-256-GCM（每个数据块独立随机 96 位 nonce，AAD 绑定块序号）。
/// 密钥派生：PBKDF2-HMAC-SHA256，每个容器独立随机盐，DEK 由密码/恢复码派生出的 KEK 再以 AES-GCM 包装。
/// 头部由 DEK 派生的 HMAC-SHA256 认证，防止篡改 flags / KDF 参数；结束块认证并记录块数与字节数，可检测截断。
/// v1 容器（无头部 HMAC、以 4 字节 0 作为结束标记）仍然可读，写入统一使用 v2。
/// </summary>
public sealed class VaultEncryptor
{
    public const string Extension = ".flvault";

    private const string Magic = "FLVLT1";

    private const byte LegacyVersion = 1;

    private const byte CurrentVersion = 2;

    private const int ChunkSize = 64 * 1024;

    private const int SaltSize = 16;

    private const int KeySize = 32;

    private const int NonceSize = 12;

    private const int TagSize = 16;

    private const int WrappedSize = NonceSize + KeySize + TagSize;

    private const int HeaderMacSize = 32;

    private const int BaseHeaderSize = 6 + 1 + 1 + 4 + SaltSize + SaltSize + WrappedSize + WrappedSize;

    private const int HeaderSizeV2 = BaseHeaderSize + HeaderMacSize;

    private const int TrailerMarker = -1;

    private const int TrailerPlainSize = 16;

    /// <summary>允许的最大 KDF 迭代次数，避免被篡改的头部造成超长计算（拒绝服务）。</summary>
    private const int MaxIterations = 5_000_000;

    public string EncryptDirectory(
        string sourceDirectory,
        string vaultPath,
        ReadOnlySpan<char> password,
        string? recoveryCode,
        int iterations = PasswordHasher.DefaultIterations,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default,
        bool compress = false,
        bool overwrite = false,
        VaultEncryptionReport? report = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        if (password.IsEmpty)
        {
            throw new ArgumentException("Password must not be empty.", nameof(password));
        }

        if (iterations <= 0 || iterations > MaxIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sourceDirectory));
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException($"Directory not found: {root}");
        }

        var vaultFull = Path.GetFullPath(vaultPath);
        if (File.Exists(vaultFull) && !overwrite)
        {
            throw new VaultException($"目标加密容器已存在，拒绝覆盖：{vaultFull}");
        }

        var entries = new List<Entry>();
        CollectEntries(root, root, entries, report, cancellationToken);

        long total = 0;
        foreach (var entry in entries)
        {
            if (!entry.IsDirectory)
            {
                total += new FileInfo(entry.FullPath!).Length;
            }
        }

        progress?.Report(new VaultProgress(0, total));

        var dek = RandomNumberGenerator.GetBytes(KeySize);
        var saltPassword = RandomNumberGenerator.GetBytes(SaltSize);
        var saltRecovery = RandomNumberGenerator.GetBytes(SaltSize);
        var hasRecovery = !string.IsNullOrWhiteSpace(recoveryCode);

        var parent = Path.GetDirectoryName(vaultFull);
        if (!string.IsNullOrEmpty(parent))
        {
            Directory.CreateDirectory(parent);
        }

        var tempPath = vaultFull + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            var kekPassword = PasswordHasher.Derive(password, saltPassword, iterations, KeySize);
            var wrappedPassword = WrapKey(kekPassword, dek);
            Array.Clear(kekPassword);

            var wrappedRecovery = new byte[WrappedSize];
            if (hasRecovery)
            {
                var kekRecovery = PasswordHasher.Derive(
                    RecoveryCode.Normalize(recoveryCode!),
                    saltRecovery,
                    iterations,
                    KeySize);
                wrappedRecovery = WrapKey(kekRecovery, dek);
                Array.Clear(kekRecovery);
            }

            var headerPrefix = BuildHeaderPrefix(
                CurrentVersion,
                hasRecovery,
                compress,
                iterations,
                saltPassword,
                saltRecovery,
                wrappedPassword,
                wrappedRecovery);
            var headerMac = ComputeHeaderMac(dek, headerPrefix);

            using (var output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var gcm = new AesGcm(dek, TagSize))
            {
                output.Write(headerPrefix);
                output.Write(headerMac);

                var writer = new ChunkedAeadWriter(output, gcm, cancellationToken);
                Stream payload = compress
                    ? new GZipStream(writer, CompressionLevel.Fastest, leaveOpen: true)
                    : writer;

                using (var binary = new BinaryWriter(payload, Encoding.UTF8, leaveOpen: false))
                {
                    WritePayload(binary, entries, progress, total, cancellationToken);
                }

                writer.Complete();
                output.Flush(flushToDisk: true);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(tempPath, vaultFull, overwrite: false);
            progress?.Report(new VaultProgress(total, total));
            return vaultFull;
        }
        catch
        {
            TryDeleteTemp(tempPath);
            throw;
        }
        finally
        {
            Array.Clear(dek);
        }
    }

    public void DecryptToDirectory(
        string vaultPath,
        string targetDirectory,
        ReadOnlySpan<char> secret,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetDirectory);
        Process(vaultPath, secret, Path.GetFullPath(targetDirectory), progress, cancellationToken);
    }

    public void Verify(
        string vaultPath,
        ReadOnlySpan<char> secret,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        Process(vaultPath, secret, targetDirectory: null, progress, cancellationToken);
    }

    private static void Process(
        string vaultPath,
        ReadOnlySpan<char> secret,
        string? targetDirectory,
        IProgress<VaultProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        if (secret.IsEmpty)
        {
            throw new ArgumentException("Secret must not be empty.", nameof(secret));
        }

        cancellationToken.ThrowIfCancellationRequested();

        using var input = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var header = ReadHeader(input);
        var headerSize = HeaderSizeFor(header.Version);
        var total = Math.Max(0, input.Length - headerSize);
        progress?.Report(new VaultProgress(0, total));

        var dek = Unwrap(header, secret);
        try
        {
            if (header.Version >= CurrentVersion)
            {
                VerifyHeaderMac(header, dek);
            }

            if (targetDirectory is not null)
            {
                Directory.CreateDirectory(targetDirectory);
            }

            ProcessPayload(
                input,
                dek,
                targetDirectory,
                progress,
                total,
                headerSize,
                cancellationToken,
                header.IsCompressed,
                requireTrailer: header.Version >= CurrentVersion);

            progress?.Report(new VaultProgress(total, total));
        }
        finally
        {
            Array.Clear(dek);
        }
    }

    public VaultHeaderInfo ReadHeaderInfo(string vaultPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);

        using var input = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var header = ReadHeader(input);
        return new VaultHeaderInfo(header.Version, header.HasRecovery, header.IsCompressed, header.Iterations, input.Length);
    }

    public bool TryVerify(string vaultPath, ReadOnlySpan<char> secret)
    {
        try
        {
            Verify(vaultPath, secret);
            return true;
        }
        catch (Exception ex) when (IsVerificationFailure(ex))
        {
            return false;
        }
    }

    public SalvageResult SalvageToDirectory(string vaultPath, string targetDirectory, ReadOnlySpan<char> secret)
    {
        try
        {
            DecryptToDirectory(vaultPath, targetDirectory, secret);
            return new SalvageResult(true, null);
        }
        catch (Exception ex) when (IsVerificationFailure(ex) || ex is IOException or UnauthorizedAccessException)
        {
            return new SalvageResult(false, ex.Message);
        }
    }

    private static bool IsVerificationFailure(Exception ex)
    {
        return ex is VaultException
            or IOException
            or UnauthorizedAccessException
            or CryptographicException
            or ArgumentException
            or NotSupportedException;
    }

    private static int HeaderSizeFor(byte version) => version >= CurrentVersion ? HeaderSizeV2 : BaseHeaderSize;

    private static void TryDeleteTemp(string path)
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

    private static byte[] Unwrap(Header header, ReadOnlySpan<char> secret)
    {
        var kekPassword = PasswordHasher.Derive(secret, header.SaltPassword, header.Iterations, KeySize);
        var dek = UnwrapKey(kekPassword, header.WrappedByPassword);
        Array.Clear(kekPassword);
        if (dek is not null)
        {
            return dek;
        }

        if (header.HasRecovery)
        {
            var kekRecovery = PasswordHasher.Derive(
                RecoveryCode.Normalize(secret),
                header.SaltRecovery,
                header.Iterations,
                KeySize);
            dek = UnwrapKey(kekRecovery, header.WrappedByRecovery);
            Array.Clear(kekRecovery);
            if (dek is not null)
            {
                return dek;
            }
        }

        throw new VaultException("密码或恢复码不正确。");
    }

    private static void WritePayload(
        BinaryWriter binary,
        List<Entry> entries,
        IProgress<VaultProgress>? progress,
        long total,
        CancellationToken cancellationToken)
    {
        long processed = 0;
        binary.Write(entries.Count);
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            binary.Write(entry.IsDirectory ? (byte)1 : (byte)0);

            var relative = Encoding.UTF8.GetBytes(entry.RelativePath);
            binary.Write(relative.Length);
            binary.Write(relative);
            binary.Write(entry.LastWriteTicks);

            if (entry.IsDirectory)
            {
                continue;
            }

            var length = new FileInfo(entry.FullPath!).Length;
            binary.Write(length);

            using var source = new FileStream(entry.FullPath!, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buffer = new byte[81920];
            long remaining = length;
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var read = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (read <= 0)
                {
                    throw new VaultException($"文件在读取过程中被截断：{entry.RelativePath}");
                }

                binary.Write(buffer, 0, read);
                remaining -= read;
                processed += read;
                progress?.Report(new VaultProgress(processed, total));
            }
        }
    }

    private static void ProcessPayload(
        FileStream input,
        byte[] dek,
        string? targetDirectory,
        IProgress<VaultProgress>? progress,
        long total,
        int headerSize,
        CancellationToken cancellationToken,
        bool compressed,
        bool requireTrailer)
    {
        using var gcm = new AesGcm(dek, TagSize);
        using var reader = new ChunkedAeadReader(input, gcm, cancellationToken, requireTrailer);
        Stream payload = compressed
            ? new GZipStream(reader, CompressionMode.Decompress, leaveOpen: true)
            : reader;
        using var binary = new BinaryReader(payload, Encoding.UTF8, leaveOpen: false);

        var buffer = new byte[81920];
        try
        {
            var count = binary.ReadInt32();
            if (count < 0 || count > 5_000_000)
            {
                throw new VaultException("Vault 结构损坏。");
            }

            long processed = 0;
            for (var i = 0; i < count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var kind = binary.ReadByte();
                var pathLength = binary.ReadInt32();
                if (pathLength < 0 || pathLength > 32 * 1024)
                {
                    throw new VaultException("Vault 路径长度异常。");
                }

                var pathBytes = binary.ReadBytes(pathLength);
                if (pathBytes.Length != pathLength)
                {
                    throw new VaultException("Vault 内容不完整。");
                }

                var relative = Encoding.UTF8.GetString(pathBytes);
                var ticks = binary.ReadInt64();
                var target = ResolveTarget(targetDirectory, relative);

                if (kind == 1)
                {
                    if (target is not null)
                    {
                        Directory.CreateDirectory(target);
                        Directory.SetLastWriteTimeUtc(target, new DateTime(ticks, DateTimeKind.Utc));
                    }

                    continue;
                }

                if (kind != 0)
                {
                    throw new VaultException("Vault 条目类型无效。");
                }

                var size = binary.ReadInt64();
                if (size < 0)
                {
                    throw new VaultException("Vault 文件长度无效。");
                }

                FileStream? output = null;
                if (target is not null)
                {
                    var parent = Path.GetDirectoryName(target);
                    if (!string.IsNullOrEmpty(parent))
                    {
                        Directory.CreateDirectory(parent);
                    }

                    output = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None);
                }

                try
                {
                    var remaining = size;
                    while (remaining > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var read = payload.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                        if (read <= 0)
                        {
                            throw new VaultException("Vault 内容不完整。");
                        }

                        output?.Write(buffer, 0, read);
                        remaining -= read;
                        processed += read;

                        var consumed = Math.Clamp(input.Position - headerSize, 0, total);
                        progress?.Report(new VaultProgress(consumed, total));
                    }
                }
                finally
                {
                    output?.Dispose();
                }

                if (target is not null)
                {
                    File.SetLastWriteTimeUtc(target, new DateTime(ticks, DateTimeKind.Utc));
                }
            }

            // 必须读完容器尾部，才能验证结束块（截断检测）以及压缩流完整性。
            Drain(payload, buffer, cancellationToken);
            Drain(reader, buffer, cancellationToken);
        }
        catch (EndOfStreamException ex)
        {
            throw new VaultException("Vault 内容不完整，文件可能被截断。", ex);
        }
        catch (InvalidDataException ex)
        {
            throw new VaultException("Vault 压缩数据损坏。", ex);
        }
    }

    private static void Drain(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (stream.Read(buffer, 0, buffer.Length) <= 0)
            {
                return;
            }
        }
    }

    private static string? ResolveTarget(string? targetDirectory, string relative)
    {
        if (string.IsNullOrEmpty(relative) ||
            relative.Contains(':') ||
            relative.StartsWith('/') ||
            relative.StartsWith('\\'))
        {
            throw new VaultException("Vault 包含非法路径。");
        }

        var invalid = Path.GetInvalidFileNameChars();
        var parts = relative.Split('/');
        foreach (var part in parts)
        {
            // 片段中不允许出现任何 Windows 非法文件名字符（含 '\'），否则可能借由
            // "sub/..\..\evil" 这类片段逃逸出目标目录。
            if (part.Length == 0 ||
                part == "." ||
                part == ".." ||
                part.IndexOfAny(invalid) >= 0 ||
                part.EndsWith(' ') ||
                part.EndsWith('.'))
            {
                throw new VaultException("Vault 包含非法路径。");
            }
        }

        if (targetDirectory is null)
        {
            return null;
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(targetDirectory));
        var current = root;
        foreach (var part in parts)
        {
            current = Path.Combine(current, part);
        }

        var full = Path.GetFullPath(current);
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new VaultException("Vault 包含非法路径。");
        }

        return full;
    }

    private static void CollectEntries(
        string root,
        string current,
        List<Entry> entries,
        VaultEncryptionReport? report,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var directory in Directory.EnumerateDirectories(current))
        {
            var attributes = File.GetAttributes(directory);
            var relative = Path.GetRelativePath(root, directory).Replace('\\', '/');
            entries.Add(new Entry(relative, true, null, Directory.GetLastWriteTimeUtc(directory).Ticks));

            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                // 目录联接/符号链接只保留一个空目录占位，目标内容不会被加密，必须让调用方明确告知用户。
                report?.SkippedEntries.Add($"{relative}（目录联接/符号链接，指向的内容未加密）");
                continue;
            }

            CollectEntries(root, directory, entries, report, cancellationToken);
        }

        foreach (var file in Directory.EnumerateFiles(current))
        {
            var attributes = File.GetAttributes(file);
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');

            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                report?.SkippedEntries.Add($"{relative}（符号链接文件，未加密）");
                continue;
            }

            entries.Add(new Entry(relative, false, file, File.GetLastWriteTimeUtc(file).Ticks));
        }
    }

    private static byte[] BuildHeaderPrefix(
        byte version,
        bool hasRecovery,
        bool compressed,
        int iterations,
        byte[] saltPassword,
        byte[] saltRecovery,
        byte[] wrappedPassword,
        byte[] wrappedRecovery)
    {
        var prefix = new byte[BaseHeaderSize];
        Encoding.ASCII.GetBytes(Magic).CopyTo(prefix, 0);
        prefix[6] = version;
        prefix[7] = (byte)((hasRecovery ? 1 : 0) | (compressed ? 2 : 0));
        BinaryPrimitives.WriteInt32LittleEndian(prefix.AsSpan(8, 4), iterations);
        saltPassword.CopyTo(prefix, 12);
        saltRecovery.CopyTo(prefix, 28);
        wrappedPassword.CopyTo(prefix, 44);
        wrappedRecovery.CopyTo(prefix, 44 + WrappedSize);
        return prefix;
    }

    private static byte[] ComputeHeaderMac(byte[] dek, byte[] headerPrefix)
    {
        using var hmac = new HMACSHA256(dek);
        return hmac.ComputeHash(headerPrefix);
    }

    private static void VerifyHeaderMac(Header header, byte[] dek)
    {
        if (header.Mac is null)
        {
            throw new VaultException("Vault 头部校验失败，文件可能被篡改。");
        }

        var expected = ComputeHeaderMac(dek, header.RawPrefix);
        if (!CryptographicOperations.FixedTimeEquals(expected, header.Mac))
        {
            throw new VaultException("Vault 头部校验失败，文件可能被篡改。");
        }
    }

    private static Header ReadHeader(Stream input)
    {
        var prefix = new byte[BaseHeaderSize];
        try
        {
            input.ReadExactly(prefix);
        }
        catch (EndOfStreamException ex)
        {
            throw new VaultException("Vault 文件损坏或长度不足。", ex);
        }

        if (!prefix.AsSpan(0, 6).SequenceEqual(Encoding.ASCII.GetBytes(Magic)))
        {
            throw new VaultException("不是有效的 FolderLock Vault 文件。");
        }

        var version = prefix[6];
        if (version is not (LegacyVersion or CurrentVersion))
        {
            throw new VaultException($"不支持的 Vault 版本：{version}");
        }

        var flags = prefix[7];
        var hasRecovery = (flags & 1) != 0;
        var compressed = (flags & 2) != 0;

        var iterations = BinaryPrimitives.ReadInt32LittleEndian(prefix.AsSpan(8, 4));
        if (iterations <= 0 || iterations > MaxIterations)
        {
            throw new VaultException("Vault KDF 参数无效。");
        }

        byte[] mac = Array.Empty<byte>();
        if (version >= CurrentVersion)
        {
            mac = new byte[HeaderMacSize];
            try
            {
                input.ReadExactly(mac);
            }
            catch (EndOfStreamException ex)
            {
                throw new VaultException("Vault 文件损坏或长度不足。", ex);
            }
        }

        return new Header(
            version,
            hasRecovery,
            compressed,
            iterations,
            prefix.AsSpan(12, SaltSize).ToArray(),
            prefix.AsSpan(28, SaltSize).ToArray(),
            prefix.AsSpan(44, WrappedSize).ToArray(),
            prefix.AsSpan(44 + WrappedSize, WrappedSize).ToArray(),
            prefix,
            mac);
    }

    private static byte[] WrapKey(byte[] kek, byte[] dek)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[dek.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(kek, TagSize);
        gcm.Encrypt(nonce, dek, ciphertext, tag);

        var result = new byte[WrappedSize];
        nonce.CopyTo(result, 0);
        ciphertext.CopyTo(result, NonceSize);
        tag.CopyTo(result, NonceSize + dek.Length);
        return result;
    }

    private static byte[]? UnwrapKey(byte[] kek, byte[] blob)
    {
        if (blob.Length != WrappedSize)
        {
            return null;
        }

        var nonce = blob.AsSpan(0, NonceSize);
        var ciphertext = blob.AsSpan(NonceSize, KeySize);
        var tag = blob.AsSpan(NonceSize + KeySize, TagSize);
        var dek = new byte[KeySize];

        try
        {
            using var gcm = new AesGcm(kek, TagSize);
            gcm.Decrypt(nonce, ciphertext, tag, dek);
            return dek;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private readonly record struct Entry(string RelativePath, bool IsDirectory, string? FullPath, long LastWriteTicks);

    private sealed record Header(
        byte Version,
        bool HasRecovery,
        bool IsCompressed,
        int Iterations,
        byte[] SaltPassword,
        byte[] SaltRecovery,
        byte[] WrappedByPassword,
        byte[] WrappedByRecovery,
        byte[] RawPrefix,
        byte[] Mac);

    private sealed class ChunkedAeadWriter : Stream
    {
        private readonly Stream _output;
        private readonly AesGcm _gcm;
        private readonly CancellationToken _cancellationToken;
        private readonly byte[] _buffer = new byte[ChunkSize];
        private int _buffered;
        private long _index;
        private long _total;

        public ChunkedAeadWriter(Stream output, AesGcm gcm, CancellationToken cancellationToken)
        {
            _output = output;
            _gcm = gcm;
            _cancellationToken = cancellationToken;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            _total += buffer.Length;

            while (!buffer.IsEmpty)
            {
                _cancellationToken.ThrowIfCancellationRequested();

                var take = Math.Min(ChunkSize - _buffered, buffer.Length);
                buffer[..take].CopyTo(_buffer.AsSpan(_buffered));
                _buffered += take;
                buffer = buffer[take..];

                if (_buffered == ChunkSize)
                {
                    FlushChunk();
                }
            }
        }

        public void Complete()
        {
            if (_buffered > 0)
            {
                FlushChunk();
            }

            // 结束块：明文记录已写入的块数与明文总字节数，读取端据此检测截断/追加。
            var manifest = new byte[TrailerPlainSize];
            BinaryPrimitives.WriteInt64LittleEndian(manifest.AsSpan(0, 8), _index);
            BinaryPrimitives.WriteInt64LittleEndian(manifest.AsSpan(8, 8), _total);

            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[TrailerPlainSize];
            var tag = new byte[TagSize];
            _gcm.Encrypt(nonce, manifest, ciphertext, tag, CreateAad(_index));

            Span<byte> marker = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(marker, TrailerMarker);
            _output.Write(marker);
            _output.Write(nonce);
            _output.Write(ciphertext);
            _output.Write(tag);
        }

        private void FlushChunk()
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[_buffered];
            var tag = new byte[TagSize];
            _gcm.Encrypt(nonce, _buffer.AsSpan(0, _buffered), ciphertext, tag, CreateAad(_index));

            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(length, _buffered);
            _output.Write(length);
            _output.Write(nonce);
            _output.Write(ciphertext);
            _output.Write(tag);

            _buffered = 0;
            _index++;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
        }
    }

    private sealed class ChunkedAeadReader : Stream
    {
        private readonly Stream _input;
        private readonly AesGcm _gcm;
        private readonly CancellationToken _cancellationToken;
        private readonly bool _requireTrailer;
        private byte[] _plain = Array.Empty<byte>();
        private int _position;
        private long _index;
        private long _total;
        private bool _ended;

        public ChunkedAeadReader(Stream input, AesGcm gcm, CancellationToken cancellationToken, bool requireTrailer)
        {
            _input = input;
            _gcm = gcm;
            _cancellationToken = cancellationToken;
            _requireTrailer = requireTrailer;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            if (buffer.IsEmpty)
            {
                return 0;
            }

            if (_position >= _plain.Length)
            {
                if (_ended || !LoadChunk())
                {
                    return 0;
                }
            }

            var take = Math.Min(buffer.Length, _plain.Length - _position);
            _plain.AsSpan(_position, take).CopyTo(buffer);
            _position += take;
            return take;
        }

        private bool LoadChunk()
        {
            _cancellationToken.ThrowIfCancellationRequested();

            Span<byte> lengthBytes = stackalloc byte[4];
            try
            {
                _input.ReadExactly(lengthBytes);
            }
            catch (EndOfStreamException ex)
            {
                // 旧实现把“提前遇到 EOF”当作正常结束，导致被截断的容器可以静默解出部分内容。
                throw new VaultException("Vault 文件不完整：数据在结束标记前中断，文件可能被截断。", ex);
            }

            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length == 0)
            {
                if (_requireTrailer)
                {
                    throw new VaultException("Vault 文件不完整：缺少已认证的结束块，文件可能被截断。");
                }

                _ended = true;
                return false;
            }

            if (length == TrailerMarker)
            {
                if (!_requireTrailer)
                {
                    throw new VaultException("Vault 数据块损坏。");
                }

                LoadTrailer();
                _ended = true;
                return false;
            }

            if (length < 0 || length > ChunkSize)
            {
                throw new VaultException("Vault 数据块损坏。");
            }

            var nonce = new byte[NonceSize];
            _input.ReadExactly(nonce);
            var ciphertext = new byte[length];
            _input.ReadExactly(ciphertext);
            var tag = new byte[TagSize];
            _input.ReadExactly(tag);

            var plain = new byte[length];
            try
            {
                _gcm.Decrypt(nonce, ciphertext, tag, plain, CreateAad(_index));
            }
            catch (CryptographicException ex)
            {
                throw new VaultException("Vault 完整性校验失败。", ex);
            }

            _plain = plain;
            _position = 0;
            _index++;
            _total += length;
            return true;
        }

        private void LoadTrailer()
        {
            var nonce = new byte[NonceSize];
            _input.ReadExactly(nonce);
            var ciphertext = new byte[TrailerPlainSize];
            _input.ReadExactly(ciphertext);
            var tag = new byte[TagSize];
            _input.ReadExactly(tag);

            var manifest = new byte[TrailerPlainSize];
            try
            {
                _gcm.Decrypt(nonce, ciphertext, tag, manifest, CreateAad(_index));
            }
            catch (CryptographicException ex)
            {
                throw new VaultException("Vault 结束块校验失败，文件可能被截断或篡改。", ex);
            }

            var chunkCount = BinaryPrimitives.ReadInt64LittleEndian(manifest.AsSpan(0, 8));
            var totalBytes = BinaryPrimitives.ReadInt64LittleEndian(manifest.AsSpan(8, 8));
            if (chunkCount != _index || totalBytes != _total)
            {
                throw new VaultException("Vault 结束块与内容不一致，文件可能被截断或篡改。");
            }
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
        }
    }

    private static byte[] CreateAad(long index)
    {
        var aad = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(aad, index);
        return aad;
    }
}
