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

public sealed class VaultEncryptor
{
    public const string Extension = ".flvault";

    private const string Magic = "FLVLT1";
    private const byte Version = 1;
    private const int ChunkSize = 64 * 1024;
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int WrappedSize = NonceSize + KeySize + TagSize;
    private const int HeaderSize = 6 + 1 + 1 + 4 + SaltSize + SaltSize + WrappedSize + WrappedSize;

    public string EncryptDirectory(
        string sourceDirectory,
        string vaultPath,
        ReadOnlySpan<char> password,
        string? recoveryCode,
        int iterations = PasswordHasher.DefaultIterations,
        IProgress<VaultProgress>? progress = null,
        CancellationToken cancellationToken = default,
        bool compress = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        if (password.IsEmpty)
        {
            throw new ArgumentException("Password must not be empty.", nameof(password));
        }

        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sourceDirectory));
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException($"Directory not found: {root}");
        }

        var entries = new List<Entry>();
        CollectEntries(root, root, entries, cancellationToken);

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

        var vaultFull = Path.GetFullPath(vaultPath);
        var parent = Path.GetDirectoryName(vaultFull);
        if (!string.IsNullOrEmpty(parent))
        {
            Directory.CreateDirectory(parent);
        }

        var tempPath = vaultFull + ".tmp";

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

            using (var output = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var gcm = new AesGcm(dek, TagSize))
            {
                WriteHeader(output, hasRecovery, compress, iterations, saltPassword, saltRecovery, wrappedPassword, wrappedRecovery);

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
            File.Move(tempPath, vaultFull, overwrite: true);
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
        var total = Math.Max(0, input.Length - HeaderSize);
        progress?.Report(new VaultProgress(0, total));

        var (dek, _, header) = Unwrap(input, secret);
        try
        {
            if (targetDirectory is not null)
            {
                Directory.CreateDirectory(targetDirectory);
            }

            ProcessPayload(input, dek, targetDirectory, progress, total, cancellationToken, header.IsCompressed);
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
        return new VaultHeaderInfo(Version, header.HasRecovery, header.IsCompressed, header.Iterations, input.Length);
    }

    public bool TryVerify(string vaultPath, ReadOnlySpan<char> secret)
    {
        try
        {
            Verify(vaultPath, secret);
            return true;
        }
        catch (VaultException)
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
        catch (VaultException ex)
        {
            return new SalvageResult(false, ex.Message);
        }
    }

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

    private static (byte[] Dek, bool UsedRecovery, Header Header) Unwrap(FileStream input, ReadOnlySpan<char> secret)
    {
        input.Position = 0;
        var header = ReadHeader(input);

        var kekPassword = PasswordHasher.Derive(secret, header.SaltPassword, header.Iterations, KeySize);
        var dek = UnwrapKey(kekPassword, header.WrappedByPassword);
        Array.Clear(kekPassword);
        if (dek is not null)
        {
            return (dek, false, header);
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
                return (dek, true, header);
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
        CancellationToken cancellationToken,
        bool compressed)
    {
        using var gcm = new AesGcm(dek, TagSize);
        using var reader = new ChunkedAeadReader(input, gcm, cancellationToken);
        Stream payload = compressed
            ? new GZipStream(reader, CompressionMode.Decompress, leaveOpen: true)
            : reader;
        using var binary = new BinaryReader(payload, Encoding.UTF8, leaveOpen: false);

        var count = binary.ReadInt32();
        if (count < 0 || count > 5_000_000)
        {
            throw new VaultException("Vault 结构损坏。");
        }

        long processed = 0;
        var buffer = new byte[81920];
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

                    var consumed = Math.Clamp(input.Position - HeaderSize, 0, total);
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

        var parts = relative.Split('/');
        foreach (var part in parts)
        {
            if (part.Length == 0 || part == "." || part == "..")
            {
                throw new VaultException("Vault 包含非法路径。");
            }
        }

        if (targetDirectory is null)
        {
            return null;
        }

        var current = targetDirectory;
        foreach (var part in parts)
        {
            current = Path.Combine(current, part);
        }

        return Path.GetFullPath(current);
    }

    private static void CollectEntries(string root, string current, List<Entry> entries, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var directory in Directory.EnumerateDirectories(current))
        {
            var attributes = File.GetAttributes(directory);
            var relative = Path.GetRelativePath(root, directory).Replace('\\', '/');
            entries.Add(new Entry(relative, true, null, Directory.GetLastWriteTimeUtc(directory).Ticks));

            if (!attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                CollectEntries(root, directory, entries, cancellationToken);
            }
        }

        foreach (var file in Directory.EnumerateFiles(current))
        {
            if (File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint))
            {
                continue;
            }

            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            entries.Add(new Entry(relative, false, file, File.GetLastWriteTimeUtc(file).Ticks));
        }
    }

    private static void WriteHeader(
        Stream output,
        bool hasRecovery,
        bool compressed,
        int iterations,
        byte[] saltPassword,
        byte[] saltRecovery,
        byte[] wrappedPassword,
        byte[] wrappedRecovery)
    {
        var flags = (byte)((hasRecovery ? 1 : 0) | (compressed ? 2 : 0));
        output.Write(Encoding.ASCII.GetBytes(Magic));
        output.WriteByte(Version);
        output.WriteByte(flags);

        Span<byte> intBuffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(intBuffer, iterations);
        output.Write(intBuffer);

        output.Write(saltPassword);
        output.Write(saltRecovery);
        output.Write(wrappedPassword);
        output.Write(wrappedRecovery);
    }

    private static Header ReadHeader(Stream input)
    {
        var magic = new byte[6];
        input.ReadExactly(magic);
        if (!magic.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes(Magic)))
        {
            throw new VaultException("不是有效的 FolderLock Vault 文件。");
        }

        var version = input.ReadByte();
        if (version != Version)
        {
            throw new VaultException($"不支持的 Vault 版本：{version}");
        }

        var flags = input.ReadByte();
        var hasRecovery = (flags & 1) != 0;
        var compressed = (flags & 2) != 0;

        var intBuffer = new byte[4];
        input.ReadExactly(intBuffer);
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(intBuffer);
        if (iterations <= 0)
        {
            throw new VaultException("Vault KDF 参数无效。");
        }

        var saltPassword = new byte[SaltSize];
        var saltRecovery = new byte[SaltSize];
        var wrappedPassword = new byte[WrappedSize];
        var wrappedRecovery = new byte[WrappedSize];
        input.ReadExactly(saltPassword);
        input.ReadExactly(saltRecovery);
        input.ReadExactly(wrappedPassword);
        input.ReadExactly(wrappedRecovery);

        return new Header(hasRecovery, compressed, iterations, saltPassword, saltRecovery, wrappedPassword, wrappedRecovery);
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

    private readonly record struct Header(
        bool HasRecovery,
        bool IsCompressed,
        int Iterations,
        byte[] SaltPassword,
        byte[] SaltRecovery,
        byte[] WrappedByPassword,
        byte[] WrappedByRecovery);

    private sealed class ChunkedAeadWriter : Stream
    {
        private readonly Stream _output;
        private readonly AesGcm _gcm;
        private readonly CancellationToken _cancellationToken;
        private readonly byte[] _buffer = new byte[ChunkSize];
        private int _buffered;
        private long _index;

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

            Span<byte> end = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(end, 0);
            _output.Write(end);
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
        private byte[] _plain = Array.Empty<byte>();
        private int _position;
        private long _index;
        private bool _ended;

        public ChunkedAeadReader(Stream input, AesGcm gcm, CancellationToken cancellationToken)
        {
            _input = input;
            _gcm = gcm;
            _cancellationToken = cancellationToken;
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
            catch (EndOfStreamException)
            {
                _ended = true;
                return false;
            }

            var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length == 0)
            {
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
            catch (CryptographicException)
            {
                throw new VaultException("Vault 完整性校验失败。");
            }

            _plain = plain;
            _position = 0;
            _index++;
            return true;
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
