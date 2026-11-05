using System.Security.Cryptography;
using System.Text;
using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class VaultSlotManagerTests : IDisposable
{
    private const string Password = "vault-password";
    private const string Recovery = "RECOVERY-CODE-1234";
    private const int Iterations = 1000;

    private readonly string _root;
    private readonly string _source;
    private readonly VaultEncryptor _vault = new();
    private readonly VaultSlotManager _slots = new();

    public VaultSlotManagerTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _source = Path.Combine(_root, "source");
        Directory.CreateDirectory(Path.Combine(_source, "sub"));
        File.WriteAllText(Path.Combine(_source, "a.txt"), "hello");
        File.WriteAllText(Path.Combine(_source, "sub", "b.txt"), "world");
    }

    [Fact]
    public void AddSlot_EmergencyPassword_UnlocksWithoutChangingPayload()
    {
        var vault = CreateVault();
        var before = PayloadHash(vault);

        var slot = _slots.AddSlot(
            vault,
            new Secret(Password),
            new VaultSlotSpec(VaultSlotKind.EmergencyPassword, "应急密码", new Secret("emergency")));

        Assert.Equal(VaultSlotKind.EmergencyPassword, slot.Kind);
        Assert.Equal(before, PayloadHash(vault));

        var restored = Path.Combine(_root, "restored-emergency");
        _vault.DecryptToDirectory(vault, restored, "emergency");
        Assert.Equal("hello", File.ReadAllText(Path.Combine(restored, "a.txt")));

        var viaRecovery = Path.Combine(_root, "restored-recovery");
        _vault.DecryptToDirectory(vault, viaRecovery, Recovery);
        Assert.Equal("world", File.ReadAllText(Path.Combine(viaRecovery, "sub", "b.txt")));
    }

    [Fact]
    public void RemoveSlot_RevokesSecretAndKeepsPayload()
    {
        var vault = CreateVault();
        var slot = _slots.AddSlot(
            vault,
            new Secret(Password),
            new VaultSlotSpec(VaultSlotKind.EmergencyPassword, "应急密码", new Secret("emergency")));
        var before = PayloadHash(vault);

        _slots.RemoveSlot(vault, new Secret(Password), slot.Id);

        Assert.Equal(before, PayloadHash(vault));
        Assert.Throws<VaultException>(() => _vault.Verify(vault, "emergency"));
        _vault.Verify(vault, Password);
    }

    [Fact]
    public void ReplaceSlot_RotatesPasswordWithoutChangingPayload()
    {
        var vault = CreateVault();
        var passwordSlot = _slots.ListSlots(vault)
            .First(slot => slot.Kind == VaultSlotKind.Password);
        var before = PayloadHash(vault);

        _slots.ReplaceSlot(
            vault,
            new Secret(Password),
            passwordSlot.Id,
            new VaultSlotSpec(VaultSlotKind.Password, "主密码", new Secret("new-password")));

        Assert.Equal(before, PayloadHash(vault));
        Assert.Throws<VaultException>(() => _vault.Verify(vault, Password));
        _vault.Verify(vault, "new-password");
        _vault.Verify(vault, Recovery);

        var after = _slots.ListSlots(vault);
        Assert.Equal(passwordSlot.Id, after.Single(slot => slot.Kind == VaultSlotKind.Password).Id);
    }

    [Fact]
    public void RemoveSlot_RejectsRemovingLastPassword()
    {
        var vault = CreateVault();
        var passwordSlot = _slots.ListSlots(vault)
            .Single(slot => slot.Kind == VaultSlotKind.Password);

        var error = Assert.Throws<VaultException>(
            () => _slots.RemoveSlot(vault, new Secret(Password), passwordSlot.Id));
        Assert.Contains("至少保留一个主密码槽", error.Message);
    }

    [Fact]
    public void AddSlot_RejectsMoreThanEightSlots()
    {
        var vault = CreateVault();
        for (var i = 0; i < 6; i++)
        {
            _slots.AddSlot(
                vault,
                new Secret(Password),
                new VaultSlotSpec(
                    VaultSlotKind.EmergencyPassword,
                    $"应急 {i}",
                    new Secret($"emergency-{i}")));
        }

        Assert.Equal(8, _slots.ListSlots(vault).Count);
        Assert.Throws<VaultException>(() => _slots.AddSlot(
            vault,
            new Secret(Password),
            new VaultSlotSpec(
                VaultSlotKind.EmergencyPassword,
                "第九个",
                new Secret("too-many"))));
    }

    [Fact]
    public void UpgradeToV3_PreservesPayloadAndCreatesBackup()
    {
        var vault = Path.Combine(_root, "legacy.flvault");
        LegacyVaultV2Writer.Write(_source, vault, Password, Recovery, Iterations);
        var oldInfo = _vault.ReadHeaderInfo(vault);
        Assert.Equal(2, oldInfo.Version);

        var before = PayloadHash(vault, headerSize: 196);
        var slots = _slots.UpgradeToV3(vault, new Secret(Password), keepBackup: true);

        Assert.Equal(2, slots.Count);
        Assert.True(File.Exists(vault + ".bak"));
        Assert.Equal(2, _vault.ReadHeaderInfo(vault + ".bak").Version);

        var newInfo = _vault.ReadHeaderInfo(vault);
        Assert.Equal(3, newInfo.Version);
        Assert.Equal(before, PayloadHash(vault, headerSize: 4096));
        Assert.Equal(2, _slots.ListSlots(vault).Count);

        var restored = Path.Combine(_root, "restored-upgrade");
        _vault.DecryptToDirectory(vault, restored, Password);
        Assert.Equal("hello", File.ReadAllText(Path.Combine(restored, "a.txt")));
        _vault.Verify(vault, Recovery);
    }

    [Fact]
    public void V3Header_DoesNotContainPlaintextRecoveryCode()
    {
        var vault = CreateVault();
        var header = File.ReadAllBytes(vault).AsSpan(0, VaultHeaderV3.HeaderSize).ToArray();
        Assert.DoesNotContain(Recovery, Encoding.UTF8.GetString(header));
    }

    [Fact]
    public void AddMachineSlot_UnlocksWithMachineKeyOnly()
    {
        var vault = CreateVault();
        var machineKey = RandomNumberGenerator.GetBytes(32);
        _slots.AddSlot(
            vault,
            new Secret(Password),
            new VaultSlotSpec(VaultSlotKind.DpapiUser, "本机", MachineKey: machineKey));

        var restored = Path.Combine(_root, "restored-machine");
        _vault.DecryptToDirectory(
            vault,
            restored,
            ReadOnlySpan<char>.Empty,
            machineKey: machineKey);
        Assert.Equal("hello", File.ReadAllText(Path.Combine(restored, "a.txt")));
    }

    private string CreateVault()
    {
        var vault = Path.Combine(_root, "vault.flvault");
        _vault.EncryptDirectory(_source, vault, Password, Recovery, Iterations);
        return vault;
    }

    private static string PayloadHash(string vault, int headerSize = 4096)
    {
        using var input = new FileStream(vault, FileMode.Open, FileAccess.Read, FileShare.Read);
        input.Position = headerSize;
        using var hash = SHA256.Create();
        return Convert.ToHexString(hash.ComputeHash(input));
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
