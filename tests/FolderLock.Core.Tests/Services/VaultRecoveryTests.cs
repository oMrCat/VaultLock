using System.Security.Cryptography;
using FolderLock.Core.Security;
using FolderLock.Core.Services;
using FolderLock.Core.Tests.Security;

namespace FolderLock.Core.Tests.Services;

public sealed class VaultRecoveryTests : IDisposable
{
    private const string Password = "vault-password";
    private const string Recovery = "RECOVERY-CODE-1234";
    private const string Emergency = "emergency-password";
    private const int Iterations = 1000;

    private readonly string _root;
    private readonly string _source;
    private readonly VaultEncryptor _vault = new();
    private readonly VaultRecovery _recovery = new();

    public VaultRecoveryTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _source = Path.Combine(_root, "source");
        Directory.CreateDirectory(_source);
        File.WriteAllText(Path.Combine(_source, "a.txt"), "hello");
    }

    [Fact]
    public void Plan_V3_ListsAvailableChannelsAndPlaceholders()
    {
        var vault = CreateV3(withEmergency: true);

        var plan = _recovery.Plan(vault);

        Assert.Equal(3, plan.Version);
        Assert.Equal(4, plan.Channels.Count);
        Assert.True(Channel(plan, VaultRecoveryChannelType.RecoveryCode).Available);
        Assert.True(Channel(plan, VaultRecoveryChannelType.EmergencyPassword).Available);
        Assert.False(Channel(plan, VaultRecoveryChannelType.DpapiUser).Available);
        Assert.False(Channel(plan, VaultRecoveryChannelType.RecoveryKit).Available);
    }

    [Fact]
    public void Plan_V3_UsesSlotLabelsFromDatabase()
    {
        var vault = CreateV3(withEmergency: true);
        var slots = VaultHeaderV3.ReadFromFile(vault).Slots;
        var records = slots.Select(slot => new FolderLock.Core.Data.VaultKeySlotRecord
        {
            SlotId = slot.Id,
            FolderId = 1,
            Kind = slot.Kind,
            Label = slot.Kind == VaultSlotKind.EmergencyPassword ? "紧急备用" : null,
        }).ToList();

        var plan = _recovery.Plan(vault, records);

        Assert.Equal("紧急备用", Channel(plan, VaultRecoveryChannelType.EmergencyPassword).Label);
        Assert.Equal("恢复码", Channel(plan, VaultRecoveryChannelType.RecoveryCode).Label);
    }

    [Fact]
    public void Plan_V3_MachineSlotAvailableOnlyWithMachineKey()
    {
        var vault = CreateV3(withEmergency: false);
        var machineKey = RandomNumberGenerator.GetBytes(32);
        new VaultSlotManager(_vault).AddSlot(
            vault,
            new Secret(Password),
            new VaultSlotSpec(VaultSlotKind.DpapiUser, "本机", MachineKey: machineKey));

        Assert.False(Channel(_recovery.Plan(vault), VaultRecoveryChannelType.DpapiUser).Available);
        Assert.True(Channel(_recovery.Plan(vault, machineKeyAvailable: true), VaultRecoveryChannelType.DpapiUser).Available);
    }

    [Fact]
    public void TryChannel_RecoveryCode_DistinguishesThreeStates()
    {
        var vault = CreateV3(withEmergency: true);

        Assert.Equal(VaultRecoveryOutcome.Success, Try(vault, VaultRecoveryChannelType.RecoveryCode, Recovery).Outcome);
        Assert.Equal(VaultRecoveryOutcome.WrongKey, Try(vault, VaultRecoveryChannelType.RecoveryCode, "wrong").Outcome);
    }

    [Fact]
    public void TryChannel_EmergencyPassword_DistinguishesThreeStates()
    {
        var vault = CreateV3(withEmergency: true);

        Assert.Equal(VaultRecoveryOutcome.Success, Try(vault, VaultRecoveryChannelType.EmergencyPassword, Emergency).Outcome);
        Assert.Equal(VaultRecoveryOutcome.WrongKey, Try(vault, VaultRecoveryChannelType.EmergencyPassword, "wrong").Outcome);
    }

    [Fact]
    public void TryChannel_MissingChannel_ReturnsChannelMissing()
    {
        var vault = CreateV3(withEmergency: false);

        Assert.Equal(
            VaultRecoveryOutcome.ChannelMissing,
            Try(vault, VaultRecoveryChannelType.EmergencyPassword, "anything").Outcome);
        Assert.Equal(
            VaultRecoveryOutcome.ChannelMissing,
            Try(vault, VaultRecoveryChannelType.RecoveryKit, "anything").Outcome);
    }

    [Fact]
    public void TryChannel_DpapiUser_RequiresMachineKey()
    {
        var vault = CreateV3(withEmergency: false);
        var machineKey = RandomNumberGenerator.GetBytes(32);
        new VaultSlotManager(_vault).AddSlot(
            vault,
            new Secret(Password),
            new VaultSlotSpec(VaultSlotKind.DpapiUser, "本机", MachineKey: machineKey));

        Assert.Equal(
            VaultRecoveryOutcome.ChannelMissing,
            _recovery.TryChannel(vault, VaultRecoveryChannelType.DpapiUser, new Secret("")).Outcome);
        Assert.Equal(
            VaultRecoveryOutcome.Success,
            _recovery.TryChannel(vault, VaultRecoveryChannelType.DpapiUser, new Secret(""), machineKey).Outcome);
        Assert.Equal(
            VaultRecoveryOutcome.WrongKey,
            _recovery.TryChannel(vault, VaultRecoveryChannelType.DpapiUser, new Secret(""), RandomNumberGenerator.GetBytes(32)).Outcome);
    }

    [Fact]
    public void Plan_V2_OnlyRecoveryCodeIsAvailable()
    {
        var vault = Path.Combine(_root, "legacy.flvault");
        LegacyVaultV2Writer.Write(_source, vault, Password, Recovery, Iterations);

        var plan = _recovery.Plan(vault);

        Assert.Equal(2, plan.Version);
        Assert.True(Channel(plan, VaultRecoveryChannelType.RecoveryCode).Available);
        Assert.False(Channel(plan, VaultRecoveryChannelType.EmergencyPassword).Available);
        Assert.False(Channel(plan, VaultRecoveryChannelType.DpapiUser).Available);
    }

    [Fact]
    public void TryChannel_V2_RecoveryCodeWorksAndEmergencyIsMissing()
    {
        var vault = Path.Combine(_root, "legacy.flvault");
        LegacyVaultV2Writer.Write(_source, vault, Password, Recovery, Iterations);

        Assert.Equal(VaultRecoveryOutcome.Success, Try(vault, VaultRecoveryChannelType.RecoveryCode, Recovery).Outcome);
        Assert.Equal(VaultRecoveryOutcome.WrongKey, Try(vault, VaultRecoveryChannelType.RecoveryCode, "wrong").Outcome);
        Assert.Equal(
            VaultRecoveryOutcome.ChannelMissing,
            Try(vault, VaultRecoveryChannelType.EmergencyPassword, Emergency).Outcome);
    }

    private VaultRecoveryResult Try(string vault, VaultRecoveryChannelType channel, string secret)
    {
        return _recovery.TryChannel(vault, channel, new Secret(secret));
    }

    private static VaultRecoveryChannel Channel(VaultRecoveryPlan plan, VaultRecoveryChannelType type)
    {
        return plan.Channels.Single(channel => channel.Type == type);
    }

    private string CreateV3(bool withEmergency)
    {
        var vault = Path.Combine(_root, "vault.flvault");
        _vault.EncryptDirectory(
            _source,
            vault,
            Password,
            Recovery,
            Iterations,
            extraSlots: withEmergency
                ? new[] { new VaultSlotSpec(VaultSlotKind.EmergencyPassword, "应急密码", new Secret(Emergency)) }
                : null);
        return vault;
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
