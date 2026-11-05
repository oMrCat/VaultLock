using System.Buffers.Binary;
using System.Security.Cryptography;

namespace FolderLock.Core.Security;

/// <summary>v3 容器头部的密钥槽类型。未知类型在读取时跳过，为后续版本预留。</summary>
public enum VaultSlotKind
{
    Password = 0,
    RecoveryCode = 1,
    EmergencyPassword = 2,
    DpapiUser = 3,
    Tpm = 4,
    WindowsHello = 5,
}

/// <summary>槽使用的密钥派生算法。Argon2id 预留（P3），MachineKek 表示外部提供的机器密钥。</summary>
public enum VaultKdf : byte
{
    Pbkdf2 = 0,
    Argon2id = 1,
    MachineKek = 2,
}

/// <summary>
/// v3 容器头部中的单个密钥槽（104 字节）。
///
/// [0..16)  槽 ID（随机 GUID，跨头部重写保持稳定）
/// [16]     类型
/// [17]     KDF
/// [18..22) KDF 参数 1（PBKDF2 迭代数 / Argon2 内存 KiB），uint32 LE
/// [22..26) KDF 参数 2（Argon2 迭代数），uint32 LE
/// [26]     KDF 参数 3（Argon2 并行度）
/// [27]     保留，必须为 0
/// [28..44) 盐（kdf=2 时全零）
/// [44..104) 封装密钥：12 nonce + 32 密文 + 16 标签
/// </summary>
public sealed class VaultKeySlot
{
    public const int Size = 104;

    public const int SaltSize = 16;

    public const int NonceSize = 12;

    public const int KeySize = 32;

    public const int TagSize = 16;

    public const int WrappedSize = NonceSize + KeySize + TagSize;

    /// <summary>允许的最大 KDF 迭代次数，防止被篡改的头部造成超长计算。</summary>
    public const int MaxIterations = 5_000_000;

    private const int IdOffset = 0;

    private const int KindOffset = 16;

    private const int KdfOffset = 17;

    private const int Param1Offset = 18;

    private const int Param2Offset = 22;

    private const int Param3Offset = 26;

    private const int ReservedOffset = 27;

    private const int SaltOffset = 28;

    private const int WrappedOffset = 44;

    public VaultKeySlot(
        Guid id,
        VaultSlotKind kind,
        VaultKdf kdf,
        uint param1,
        uint param2,
        byte param3,
        byte[] salt,
        byte[] wrapped)
    {
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(wrapped);
        if (salt.Length != SaltSize)
        {
            throw new ArgumentException($"盐长度必须为 {SaltSize} 字节。", nameof(salt));
        }

        if (wrapped.Length != WrappedSize)
        {
            throw new ArgumentException($"封装密钥长度必须为 {WrappedSize} 字节。", nameof(wrapped));
        }

        Id = id;
        Kind = kind;
        Kdf = kdf;
        Param1 = param1;
        Param2 = param2;
        Param3 = param3;
        Salt = (byte[])salt.Clone();
        Wrapped = (byte[])wrapped.Clone();
    }

    public Guid Id { get; }

    public VaultSlotKind Kind { get; }

    public VaultKdf Kdf { get; }

    public uint Param1 { get; }

    public uint Param2 { get; }

    public byte Param3 { get; }

    public byte[] Salt { get; }

    public byte[] Wrapped { get; }

    /// <summary>本实现是否支持该类型。Tpm/WindowsHello 仅预留，读取时跳过。</summary>
    public bool IsSupportedKind => Kind is VaultSlotKind.Password
        or VaultSlotKind.RecoveryCode
        or VaultSlotKind.EmergencyPassword
        or VaultSlotKind.DpapiUser;

    public static VaultKeySlot Read(ReadOnlySpan<byte> raw)
    {
        if (raw.Length != Size)
        {
            throw new ArgumentException($"密钥槽长度必须为 {Size} 字节。", nameof(raw));
        }

        var idBytes = raw.Slice(IdOffset, 16);
        var id = new Guid(idBytes);
        var kind = (VaultSlotKind)raw[KindOffset];
        var kdf = (VaultKdf)raw[KdfOffset];
        var param1 = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(Param1Offset, 4));
        var param2 = BinaryPrimitives.ReadUInt32LittleEndian(raw.Slice(Param2Offset, 4));
        var param3 = raw[Param3Offset];

        return new VaultKeySlot(
            id,
            kind,
            kdf,
            param1,
            param2,
            param3,
            raw.Slice(SaltOffset, SaltSize).ToArray(),
            raw.Slice(WrappedOffset, WrappedSize).ToArray());
    }

    public void Write(Span<byte> raw)
    {
        if (raw.Length != Size)
        {
            throw new ArgumentException($"密钥槽长度必须为 {Size} 字节。", nameof(raw));
        }

        raw.Clear();
        Id.ToByteArray().CopyTo(raw.Slice(IdOffset, 16));
        raw[KindOffset] = (byte)Kind;
        raw[KdfOffset] = (byte)Kdf;
        BinaryPrimitives.WriteUInt32LittleEndian(raw.Slice(Param1Offset, 4), Param1);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.Slice(Param2Offset, 4), Param2);
        raw[Param3Offset] = Param3;
        raw[ReservedOffset] = 0;
        Salt.CopyTo(raw.Slice(SaltOffset, SaltSize));
        Wrapped.CopyTo(raw.Slice(WrappedOffset, WrappedSize));
    }

    /// <summary>用密码类秘密创建槽：PBKDF2 派生 KEK 后以 AES-GCM 封装 DEK。</summary>
    public static VaultKeySlot CreateForSecret(
        VaultSlotKind kind,
        ReadOnlySpan<char> secret,
        byte[] dek,
        int iterations = PasswordHasher.DefaultIterations,
        Guid? id = null)
    {
        ArgumentNullException.ThrowIfNull(dek);
        if (secret.IsEmpty)
        {
            throw new ArgumentException("秘密不能为空。", nameof(secret));
        }

        if (iterations <= 0 || iterations > MaxIterations)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var kek = kind == VaultSlotKind.RecoveryCode
            ? PasswordHasher.Derive(RecoveryCode.Normalize(secret), salt, iterations, KeySize)
            : PasswordHasher.Derive(secret, salt, iterations, KeySize);

        try
        {
            return new VaultKeySlot(
                id ?? Guid.NewGuid(),
                kind,
                VaultKdf.Pbkdf2,
                (uint)iterations,
                0,
                0,
                salt,
                WrapKey(kek, dek));
        }
        finally
        {
            Array.Clear(kek);
        }
    }

    /// <summary>用外部提供的 32 字节机器 KEK 创建槽（kdf=2，盐与参数全零）。</summary>
    public static VaultKeySlot CreateForMachineKey(
        VaultSlotKind kind,
        byte[] machineKey,
        byte[] dek,
        Guid? id = null)
    {
        ArgumentNullException.ThrowIfNull(machineKey);
        ArgumentNullException.ThrowIfNull(dek);
        if (machineKey.Length != KeySize)
        {
            throw new ArgumentException($"机器密钥长度必须为 {KeySize} 字节。", nameof(machineKey));
        }

        return new VaultKeySlot(
            id ?? Guid.NewGuid(),
            kind,
            VaultKdf.MachineKek,
            0,
            0,
            0,
            new byte[SaltSize],
            WrapKey(machineKey, dek));
    }

    /// <summary>尝试用密码/恢复码解开该槽，失败返回 null（调用方负责区分“槽不存在”与“密钥错误”）。</summary>
    public byte[]? TryUnwrapSecret(ReadOnlySpan<char> secret)
    {
        if (Kdf != VaultKdf.Pbkdf2 || secret.IsEmpty)
        {
            return null;
        }

        var iterations = (int)Param1;
        if (iterations <= 0 || iterations > MaxIterations)
        {
            return null;
        }

        byte[] kek;
        if (Kind == VaultSlotKind.RecoveryCode)
        {
            var normalized = RecoveryCode.Normalize(secret);
            if (normalized.Length == 0)
            {
                return null;
            }

            kek = PasswordHasher.Derive(normalized, Salt, iterations, KeySize);
        }
        else
        {
            kek = PasswordHasher.Derive(secret, Salt, iterations, KeySize);
        }

        try
        {
            return TryUnwrapKey(kek, Wrapped);
        }
        finally
        {
            Array.Clear(kek);
        }
    }

    /// <summary>尝试用机器 KEK 解开 kdf=2 槽。</summary>
    public byte[]? TryUnwrapMachine(byte[] machineKey)
    {
        if (Kdf != VaultKdf.MachineKek || machineKey.Length != KeySize)
        {
            return null;
        }

        return TryUnwrapKey(machineKey, Wrapped);
    }

    public static byte[] WrapKey(byte[] kek, byte[] dek)
    {
        ArgumentNullException.ThrowIfNull(kek);
        ArgumentNullException.ThrowIfNull(dek);
        if (kek.Length != KeySize || dek.Length != KeySize)
        {
            throw new ArgumentException("KEK 与 DEK 都必须为 32 字节。");
        }

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

    public static byte[]? TryUnwrapKey(byte[] kek, byte[] blob)
    {
        if (kek.Length != KeySize || blob.Length != WrappedSize)
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
            Array.Clear(dek);
            return null;
        }
    }
}
