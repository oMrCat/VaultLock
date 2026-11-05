using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace FolderLock.Core.Security;

/// <summary>
/// v3 容器头部：4096 字节，由 A/B 两个 2048 字节块组成，块内包含 1 到 8 个密钥槽。
/// 读取时选择“校验有效且序号最大”的块；写入时总是改写非活动块并递增序号，
/// 读回校验通过后再清零旧块，避免重写过程中崩溃导致容器不可用。
///
/// [0..6)    魔数 FLVLT1
/// [6]       版本 3
/// [7]       flags：bit0 压缩
/// [8..12)   序号 uint32 LE
/// [12]      槽数（1..8）
/// [13..16)  保留，必须为 0
/// [16..848) 槽数组（8 × 104 字节，未用槽填零）
/// [848..852) 块校验：SHA-256(块 [0..848) 的前 4 字节)
/// [852..884) HMAC-SHA256(DEK)，覆盖块 [0..852)
/// [884..2048) 保留，必须为 0
/// </summary>
public sealed class VaultHeaderV3
{
    public const byte FormatVersion = 3;

    public const int HeaderSize = 4096;

    public const int BlockSize = 2048;

    public const int MaxSlots = 8;

    public const int SlotAreaOffset = 16;

    public const int ChecksumOffset = SlotAreaOffset + MaxSlots * VaultKeySlot.Size;

    public const int ChecksumSize = 4;

    public const int HmacOffset = ChecksumOffset + ChecksumSize;

    public const int HmacSize = 32;

    public const int ReservedOffset = HmacOffset + HmacSize;

    private const int VersionOffset = 6;

    private const int FlagsOffset = 7;

    private const int SequenceOffset = 8;

    private const int SlotCountOffset = 12;

    private const int SlotReservedOffset = 27;

    private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes("FLVLT1");

    private VaultHeaderV3(
        IReadOnlyList<VaultKeySlot> slots,
        uint sequence,
        bool compressed,
        int activeBlockIndex,
        byte[] rawBlock)
    {
        Slots = slots;
        Sequence = sequence;
        IsCompressed = compressed;
        ActiveBlockIndex = activeBlockIndex;
        RawBlock = rawBlock;
    }

    public IReadOnlyList<VaultKeySlot> Slots { get; }

    public uint Sequence { get; }

    public bool IsCompressed { get; }

    /// <summary>当前生效的块下标：0 为 A 块，1 为 B 块。</summary>
    public int ActiveBlockIndex { get; }

    public byte[] RawBlock { get; }

    public bool HasRecovery => Slots.Any(slot => slot.Kind == VaultSlotKind.RecoveryCode);

    /// <summary>取第一个 PBKDF2 槽的迭代数，供旧 UI 显示。</summary>
    public int Iterations => Slots
        .Where(slot => slot.Kdf == VaultKdf.Pbkdf2)
        .Select(slot => (int)slot.Param1)
        .FirstOrDefault(PasswordHasher.DefaultIterations);

    public static VaultHeaderV3 ReadFromFile(string vaultPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);

        using var input = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Read(input);
    }

    public static VaultHeaderV3 Read(Stream input)
    {
        var raw = new byte[HeaderSize];
        try
        {
            input.Position = 0;
            input.ReadExactly(raw);
        }
        catch (EndOfStreamException ex)
        {
            throw new VaultException("Vault 文件损坏或长度不足。", ex);
        }

        ParsedBlock? best = null;
        for (var index = 0; index < 2; index++)
        {
            var start = index * BlockSize;
            var block = raw.AsSpan(start, BlockSize).ToArray();
            var parsed = TryParseBlock(block, index);
            if (parsed is null)
            {
                continue;
            }

            if (best is null || parsed.Sequence > best.Sequence)
            {
                best = parsed;
            }
        }

        if (best is null)
        {
            throw new VaultException("容器头部损坏，建议使用抢救功能或备份。");
        }

        return new VaultHeaderV3(best.Slots, best.Sequence, best.Compressed, best.Index, best.Raw);
    }

    /// <summary>用 DEK 校验活动块的 HMAC，防止 flags / 槽数组被篡改。</summary>
    public void VerifyMac(byte[] dek)
    {
        ArgumentNullException.ThrowIfNull(dek);

        var expected = ComputeMac(dek, RawBlock.AsSpan(0, HmacOffset));
        var actual = RawBlock.AsSpan(HmacOffset, HmacSize);
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
        {
            throw new VaultException("Vault 头部校验失败，文件可能被篡改。");
        }
    }

    /// <summary>按类型依次尝试槽解开 DEK，返回第一个成功的结果。</summary>
    public byte[]? TryUnwrap(ReadOnlySpan<char> secret, byte[]? machineKey)
    {
        foreach (var slot in Slots)
        {
            if (!slot.IsSupportedKind)
            {
                continue;
            }

            if (slot.Kdf == VaultKdf.MachineKek)
            {
                if (machineKey is not null)
                {
                    var dek = slot.TryUnwrapMachine(machineKey);
                    if (dek is not null)
                    {
                        return dek;
                    }
                }

                continue;
            }

            var unwrapped = slot.TryUnwrapSecret(secret);
            if (unwrapped is not null)
            {
                return unwrapped;
            }
        }

        return null;
    }

    public bool HasSecretSlots => Slots.Any(slot =>
        slot.Kdf == VaultKdf.Pbkdf2 && slot.IsSupportedKind);

    public bool HasMachineSlots => Slots.Any(slot =>
        slot.Kdf == VaultKdf.MachineKek && slot.IsSupportedKind);

    /// <summary>构造一个 2048 字节的头部块（含块校验与 DEK HMAC）。</summary>
    public static byte[] BuildBlock(
        IReadOnlyList<VaultKeySlot> slots,
        uint sequence,
        bool compressed,
        byte[] dek)
    {
        ArgumentNullException.ThrowIfNull(slots);
        ArgumentNullException.ThrowIfNull(dek);
        if (slots.Count is < 1 or > MaxSlots)
        {
            throw new VaultException($"密钥槽数量必须为 1 到 {MaxSlots}。");
        }

        var ids = new HashSet<Guid>();
        foreach (var slot in slots)
        {
            if (slot.Id == Guid.Empty || !ids.Add(slot.Id))
            {
                throw new VaultException("密钥槽 ID 为空或重复。");
            }
        }

        var block = new byte[BlockSize];
        MagicBytes.CopyTo(block, 0);
        block[VersionOffset] = FormatVersion;
        block[FlagsOffset] = (byte)(compressed ? 1 : 0);
        BinaryPrimitives.WriteUInt32LittleEndian(block.AsSpan(SequenceOffset, 4), sequence);
        block[SlotCountOffset] = (byte)slots.Count;

        for (var i = 0; i < slots.Count; i++)
        {
            slots[i].Write(block.AsSpan(SlotAreaOffset + i * VaultKeySlot.Size, VaultKeySlot.Size));
        }

        var checksum = SHA256.HashData(block.AsSpan(0, ChecksumOffset));
        checksum.AsSpan(0, ChecksumSize).CopyTo(block.AsSpan(ChecksumOffset, ChecksumSize));

        var mac = ComputeMac(dek, block.AsSpan(0, HmacOffset));
        mac.CopyTo(block, HmacOffset);
        return block;
    }

    /// <summary>把新头部块写到非活动块位置并落盘。</summary>
    public void WriteNextBlock(
        FileStream file,
        IReadOnlyList<VaultKeySlot> slots,
        bool compressed,
        byte[] dek)
    {
        ArgumentNullException.ThrowIfNull(file);

        var index = 1 - ActiveBlockIndex;
        var block = BuildBlock(slots, unchecked(Sequence + 1), compressed, dek);

        file.Position = index * BlockSize;
        file.Write(block, 0, BlockSize);
        file.Flush(flushToDisk: true);
    }

    /// <summary>新块已读回校验后清零旧块，避免旧槽继续可用。</summary>
    public void ClearInactiveBlock(FileStream file)
    {
        ArgumentNullException.ThrowIfNull(file);

        var index = ActiveBlockIndex;
        file.Position = index * BlockSize;
        file.Write(new byte[BlockSize], 0, BlockSize);
        file.Flush(flushToDisk: true);
    }

    /// <summary>新建容器时写入 A 块，B 块保持全零（无效块）。</summary>
    public static void WriteInitialHeader(FileStream file, byte[] blockA)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(blockA);
        if (blockA.Length != BlockSize)
        {
            throw new ArgumentException($"头部块长度必须为 {BlockSize} 字节。", nameof(blockA));
        }

        file.Position = 0;
        file.Write(blockA, 0, BlockSize);
        var zero = new byte[HeaderSize - BlockSize];
        file.Write(zero, 0, zero.Length);
    }

    public static bool LooksLikeV3(ReadOnlySpan<byte> prefix)
    {
        return prefix.Length >= 7 &&
               prefix[..6].SequenceEqual(MagicBytes) &&
               prefix[6] == FormatVersion;
    }

    /// <summary>
    /// 判断文件是否为 v3 容器。A/B 块写入过程中旧块可能已被清零，
    /// 因此 A 块无效时还要检查位于偏移 2048 的 B 块。
    /// </summary>
    public static bool IsV3(Stream input)
    {
        if (!input.CanSeek)
        {
            return false;
        }

        var position = input.Position;
        try
        {
            if (LooksLikeV3(ReadPrefix(input, 0)))
            {
                return true;
            }

            return input.Length >= HeaderSize && LooksLikeV3(ReadPrefix(input, BlockSize));
        }
        finally
        {
            input.Position = position;
        }
    }

    private static byte[] ReadPrefix(Stream input, int offset)
    {
        var prefix = new byte[7];
        input.Position = offset;
        input.ReadExactly(prefix);
        return prefix;
    }

    private static byte[] ComputeMac(byte[] dek, ReadOnlySpan<byte> data)
    {
        using var hmac = new HMACSHA256(dek);
        return hmac.ComputeHash(data.ToArray());
    }

    private static ParsedBlock? TryParseBlock(byte[] block, int index)
    {
        if (block.Length != BlockSize)
        {
            return null;
        }

        if (!block.AsSpan(0, 6).SequenceEqual(MagicBytes) || block[VersionOffset] != FormatVersion)
        {
            return null;
        }

        var flags = block[FlagsOffset];
        if ((flags & ~0x01) != 0)
        {
            return null;
        }

        if (!block.AsSpan(13, 3).SequenceEqual(new byte[3]) ||
            !block.AsSpan(ReservedOffset, BlockSize - ReservedOffset).SequenceEqual(
                new byte[BlockSize - ReservedOffset]))
        {
            return null;
        }

        var sequence = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(SequenceOffset, 4));
        var slotCount = block[SlotCountOffset];
        if (slotCount is < 1 or > MaxSlots)
        {
            return null;
        }

        var expectedChecksum = SHA256.HashData(block.AsSpan(0, ChecksumOffset));
        if (!expectedChecksum.AsSpan(0, ChecksumSize).SequenceEqual(
                block.AsSpan(ChecksumOffset, ChecksumSize)))
        {
            return null;
        }

        var slots = new List<VaultKeySlot>(slotCount);
        var ids = new HashSet<Guid>();
        for (var i = 0; i < slotCount; i++)
        {
            var raw = block.AsSpan(SlotAreaOffset + i * VaultKeySlot.Size, VaultKeySlot.Size);
            if (raw[SlotReservedOffset] != 0)
            {
                return null;
            }

            VaultKeySlot slot;
            try
            {
                slot = VaultKeySlot.Read(raw);
            }
            catch (ArgumentException)
            {
                return null;
            }

            if (slot.Id == Guid.Empty || !ids.Add(slot.Id))
            {
                return null;
            }

            if (!IsValidSlotParameters(slot))
            {
                return null;
            }

            slots.Add(slot);
        }

        return new ParsedBlock(slots, sequence, (flags & 0x01) != 0, index, block);
    }

    private static bool IsValidSlotParameters(VaultKeySlot slot)
    {
        if (slot.Param1 > VaultKeySlot.MaxIterations)
        {
            return false;
        }

        return slot.Kdf switch
        {
            VaultKdf.Pbkdf2 => slot.Param1 > 0,
            VaultKdf.MachineKek => slot.Param1 == 0
                && slot.Param2 == 0
                && slot.Param3 == 0
                && slot.Salt.AsSpan().SequenceEqual(new byte[VaultKeySlot.SaltSize]),
            _ => true,
        };
    }

    private sealed record ParsedBlock(
        IReadOnlyList<VaultKeySlot> Slots,
        uint Sequence,
        bool Compressed,
        int Index,
        byte[] Raw);
}
