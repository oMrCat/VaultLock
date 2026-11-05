using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class VaultHeaderV3Tests : IDisposable
{
    private readonly string _root;

    public VaultHeaderV3Tests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [Fact]
    public void BuildBlock_HasStableLayout()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var slot = VaultKeySlot.CreateForSecret(VaultSlotKind.Password, "password", dek, 1000);
        var block = VaultHeaderV3.BuildBlock(new[] { slot }, sequence: 7, compressed: true, dek);

        Assert.Equal(2048, block.Length);
        Assert.Equal("FLVLT1", Encoding.ASCII.GetString(block, 0, 6));
        Assert.Equal(3, block[6]);
        Assert.Equal(1, block[7]);
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(8, 4)));
        Assert.Equal(1, block[12]);
        Assert.True(block.AsSpan(13, 3).SequenceEqual(new byte[3]));

        var slotBytes = block.AsSpan(16, VaultKeySlot.Size).ToArray();
        var parsed = VaultKeySlot.Read(slotBytes);
        Assert.Equal(slot.Id, parsed.Id);
        Assert.Equal(VaultSlotKind.Password, parsed.Kind);
        Assert.Equal(VaultKdf.Pbkdf2, parsed.Kdf);
        Assert.Equal(1000u, parsed.Param1);
        Assert.Equal(0, parsed.Param3);
        Assert.True(slotBytes.AsSpan(27, 1).SequenceEqual(new byte[1]));

        var checksum = SHA256.HashData(block.AsSpan(0, VaultHeaderV3.ChecksumOffset));
        Assert.True(checksum.AsSpan(0, 4)
            .SequenceEqual(block.AsSpan(VaultHeaderV3.ChecksumOffset, 4)));

        using var hmac = new HMACSHA256(dek);
        var expectedMac = hmac.ComputeHash(block.AsSpan(0, VaultHeaderV3.HmacOffset).ToArray());
        Assert.True(block.AsSpan(VaultHeaderV3.HmacOffset, VaultHeaderV3.HmacSize)
            .SequenceEqual(expectedMac));

        Assert.True(block.AsSpan(VaultHeaderV3.ReservedOffset)
            .SequenceEqual(new byte[VaultHeaderV3.BlockSize - VaultHeaderV3.ReservedOffset]));
    }

    [Fact]
    public void Read_SelectsBlockWithHighestSequence()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var slotsA = new[] { VaultKeySlot.CreateForSecret(VaultSlotKind.Password, "a", dek, 1000) };
        var slotsB = new[] { VaultKeySlot.CreateForSecret(VaultSlotKind.Password, "b", dek, 1000) };

        var path = Path.Combine(_root, "seq.flvault");
        using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var blockA = VaultHeaderV3.BuildBlock(slotsA, sequence: 4, compressed: false, dek);
            var blockB = VaultHeaderV3.BuildBlock(slotsB, sequence: 9, compressed: true, dek);
            file.Write(blockA);
            file.Write(blockB);
        }

        var header = VaultHeaderV3.ReadFromFile(path);
        Assert.Equal(1, header.ActiveBlockIndex);
        Assert.Equal(9u, header.Sequence);
        Assert.True(header.IsCompressed);
        Assert.Equal(slotsB[0].Id, header.Slots[0].Id);
        header.VerifyMac(dek);
    }

    [Fact]
    public void Read_RejectsDamagedHeader()
    {
        var path = Path.Combine(_root, "damaged.flvault");
        File.WriteAllBytes(path, new byte[VaultHeaderV3.HeaderSize]);

        var error = Assert.Throws<VaultException>(() => VaultHeaderV3.ReadFromFile(path));
        Assert.Contains("头部损坏", error.Message);
    }

    [Fact]
    public void Read_RejectsTruncatedHeader()
    {
        var path = Path.Combine(_root, "truncated.flvault");
        File.WriteAllBytes(path, new byte[100]);

        Assert.Throws<VaultException>(() => VaultHeaderV3.ReadFromFile(path));
    }

    [Fact]
    public void VerifyMac_RejectsTamperedFlagsWithValidChecksum()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var slot = VaultKeySlot.CreateForSecret(VaultSlotKind.Password, "password", dek, 1000);
        var block = VaultHeaderV3.BuildBlock(new[] { slot }, 1, false, dek);

        // 修改 flags 后重新计算块校验，模拟攻击者绕过 CRC 直接改字段。
        block[7] = 0x01;
        var checksum = SHA256.HashData(block.AsSpan(0, VaultHeaderV3.ChecksumOffset));
        checksum.AsSpan(0, 4).CopyTo(block.AsSpan(VaultHeaderV3.ChecksumOffset, 4));

        var path = Path.Combine(_root, "tampered.flvault");
        using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            file.Write(block);
            file.Write(new byte[VaultHeaderV3.BlockSize]);
        }

        var header = VaultHeaderV3.ReadFromFile(path);
        var error = Assert.Throws<VaultException>(() => header.VerifyMac(dek));
        Assert.Contains("篡改", error.Message);
    }

    [Fact]
    public void Read_RejectsIterationsOverLimit()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var slot = new VaultKeySlot(
            Guid.NewGuid(),
            VaultSlotKind.Password,
            VaultKdf.Pbkdf2,
            VaultKeySlot.MaxIterations + 1,
            0,
            0,
            RandomNumberGenerator.GetBytes(16),
            RandomNumberGenerator.GetBytes(VaultKeySlot.WrappedSize));
        var block = VaultHeaderV3.BuildBlock(new[] { slot }, 1, false, dek);
        var checksum = SHA256.HashData(block.AsSpan(0, VaultHeaderV3.ChecksumOffset));
        checksum.AsSpan(0, 4).CopyTo(block.AsSpan(VaultHeaderV3.ChecksumOffset, 4));

        var path = Path.Combine(_root, "slow.flvault");
        using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            file.Write(block);
            file.Write(new byte[VaultHeaderV3.BlockSize]);
        }

        Assert.Throws<VaultException>(() => VaultHeaderV3.ReadFromFile(path));
    }

    [Fact]
    public void TryUnwrap_SkipsUnknownSlotKind()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var unknown = new VaultKeySlot(
            Guid.NewGuid(),
            (VaultSlotKind)9,
            VaultKdf.Argon2id,
            1024,
            1,
            1,
            RandomNumberGenerator.GetBytes(16),
            RandomNumberGenerator.GetBytes(VaultKeySlot.WrappedSize));
        var password = VaultKeySlot.CreateForSecret(VaultSlotKind.Password, "password", dek, 1000);
        var block = VaultHeaderV3.BuildBlock(new[] { unknown, password }, 1, false, dek);

        var path = Path.Combine(_root, "unknown.flvault");
        using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            file.Write(block);
            file.Write(new byte[VaultHeaderV3.BlockSize]);
        }

        var header = VaultHeaderV3.ReadFromFile(path);
        Assert.Equal(2, header.Slots.Count);
        var unwrapped = header.TryUnwrap("password", machineKey: null);
        Assert.NotNull(unwrapped);
        Assert.Equal(dek, unwrapped);
    }

    [Fact]
    public void WriteNextBlock_IncrementsSequenceAndClearsInactiveBlock()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var first = VaultKeySlot.CreateForSecret(VaultSlotKind.Password, "password", dek, 1000);
        var blockA = VaultHeaderV3.BuildBlock(new[] { first }, 1, false, dek);
        var path = Path.Combine(_root, "ab.flvault");

        using (var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.Read))
        {
            VaultHeaderV3.WriteInitialHeader(file, blockA);

            var header = VaultHeaderV3.Read(file);
            Assert.Equal(0, header.ActiveBlockIndex);

            var second = VaultKeySlot.CreateForSecret(VaultSlotKind.EmergencyPassword, "emergency", dek, 1000);
            header.WriteNextBlock(file, new[] { first, second }, false, dek);

            var updated = VaultHeaderV3.Read(file);
            Assert.Equal(1, updated.ActiveBlockIndex);
            Assert.Equal(2u, updated.Sequence);
            updated.VerifyMac(dek);

            header.ClearInactiveBlock(file);
            var afterClear = VaultHeaderV3.Read(file);
            Assert.Equal(1, afterClear.ActiveBlockIndex);
            Assert.Equal(2, afterClear.Slots.Count);
        }
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
