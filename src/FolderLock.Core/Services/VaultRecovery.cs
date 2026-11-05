using System.Security.Cryptography;
using FolderLock.Core.Data;
using FolderLock.Core.Security;

namespace FolderLock.Core.Services;

/// <summary>恢复向导中的通道类型。</summary>
public enum VaultRecoveryChannelType
{
    RecoveryCode,
    EmergencyPassword,
    DpapiUser,
    RecoveryKit,
}

/// <summary>单个恢复通道的可用性说明。不可用通道在 UI 中显示为灰色。</summary>
public sealed record VaultRecoveryChannel(
    VaultRecoveryChannelType Type,
    Guid? SlotId,
    string Label,
    bool Available,
    string Reason);

public sealed record VaultRecoveryPlan(int Version, IReadOnlyList<VaultRecoveryChannel> Channels);

/// <summary>恢复尝试的三种结果：通道不存在、通道存在但密钥错误、成功。</summary>
public enum VaultRecoveryOutcome
{
    ChannelMissing,
    WrongKey,
    Success,
}

public sealed record VaultRecoveryResult(VaultRecoveryOutcome Outcome, Guid? SlotId, string Message);

/// <summary>
/// “忘记密码”恢复通道探测：只读取容器头部，不要求 DEK，也不解密数据区。
/// 用于区分“这个通道不存在”和“通道存在但输入错误”，避免误导用户。
/// </summary>
public sealed class VaultRecovery
{
    private readonly VaultEncryptor _vault;

    public VaultRecovery(VaultEncryptor? vault = null)
    {
        _vault = vault ?? new VaultEncryptor();
    }

    public VaultRecoveryPlan Plan(
        string vaultPath,
        IReadOnlyList<VaultKeySlotRecord>? slotRecords = null,
        bool hasRecoveryKit = false,
        bool machineKeyAvailable = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);

        var version = ReadVersion(vaultPath);
        var channels = new List<VaultRecoveryChannel>();
        var labels = slotRecords?.ToDictionary(record => record.SlotId, record => record.Label) ?? new();

        if (version == VaultHeaderV3.FormatVersion)
        {
            var header = VaultHeaderV3.ReadFromFile(vaultPath);

            foreach (var slot in header.Slots.Where(slot => slot.Kind == VaultSlotKind.RecoveryCode))
            {
                channels.Add(new VaultRecoveryChannel(
                    VaultRecoveryChannelType.RecoveryCode,
                    slot.Id,
                    labels.GetValueOrDefault(slot.Id) ?? "恢复码",
                    true,
                    "可用"));
            }

            foreach (var slot in header.Slots.Where(slot => slot.Kind == VaultSlotKind.EmergencyPassword))
            {
                channels.Add(new VaultRecoveryChannel(
                    VaultRecoveryChannelType.EmergencyPassword,
                    slot.Id,
                    labels.GetValueOrDefault(slot.Id) ?? "应急密码",
                    true,
                    "可用"));
            }

            foreach (var slot in header.Slots.Where(slot => slot.Kind == VaultSlotKind.DpapiUser))
            {
                channels.Add(new VaultRecoveryChannel(
                    VaultRecoveryChannelType.DpapiUser,
                    slot.Id,
                    labels.GetValueOrDefault(slot.Id) ?? "本机自动解锁",
                    machineKeyAvailable,
                    machineKeyAvailable ? "可用" : "当前用户无法读取本机解锁密钥"));
            }

            AddMissingPlaceholders(channels);
        }
        else
        {
            var info = _vault.ReadHeaderInfo(vaultPath);
            channels.Add(new VaultRecoveryChannel(
                VaultRecoveryChannelType.RecoveryCode,
                null,
                "恢复码",
                info.HasRecovery,
                info.HasRecovery ? "v2 容器内置恢复码通道" : "容器中没有恢复码通道"));
            channels.Add(new VaultRecoveryChannel(
                VaultRecoveryChannelType.EmergencyPassword,
                null,
                "应急密码",
                false,
                "v2 容器不支持应急密码，请先升级到 v3"));
            channels.Add(new VaultRecoveryChannel(
                VaultRecoveryChannelType.DpapiUser,
                null,
                "本机自动解锁",
                false,
                "v2 容器不支持本机自动解锁，请先升级到 v3"));
        }

        channels.Add(new VaultRecoveryChannel(
            VaultRecoveryChannelType.RecoveryKit,
            null,
            "恢复套件",
            hasRecoveryKit,
            hasRecoveryKit ? "找到可导入的 .flkit 文件" : "未找到恢复套件（.flkit）"));

        return new VaultRecoveryPlan(version, channels);
    }

    /// <summary>
    /// 尝试某个通道。返回 ChannelMissing / WrongKey / Success，
    /// 成功时只做头部 HMAC 校验，不读取数据区。
    /// </summary>
    public VaultRecoveryResult TryChannel(
        string vaultPath,
        VaultRecoveryChannelType channel,
        Secret secret,
        byte[]? machineKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        ArgumentNullException.ThrowIfNull(secret);

        var version = ReadVersion(vaultPath);
        if (channel == VaultRecoveryChannelType.RecoveryKit)
        {
            return new VaultRecoveryResult(
                VaultRecoveryOutcome.ChannelMissing,
                null,
                "恢复套件需要通过导入流程处理，不能直接在此输入。");
        }

        if (version != VaultHeaderV3.FormatVersion)
        {
            return TryLegacy(vaultPath, channel, secret);
        }

        var header = VaultHeaderV3.ReadFromFile(vaultPath);
        var slotKind = channel switch
        {
            VaultRecoveryChannelType.RecoveryCode => VaultSlotKind.RecoveryCode,
            VaultRecoveryChannelType.EmergencyPassword => VaultSlotKind.EmergencyPassword,
            VaultRecoveryChannelType.DpapiUser => VaultSlotKind.DpapiUser,
            _ => throw new ArgumentOutOfRangeException(nameof(channel)),
        };

        var candidates = header.Slots
            .Where(slot => slot.Kind == slotKind && slot.IsSupportedKind)
            .ToList();

        if (candidates.Count == 0)
        {
            return new VaultRecoveryResult(
                VaultRecoveryOutcome.ChannelMissing,
                null,
                $"{DisplayName(channel)}通道不存在于该容器。");
        }

        if (slotKind == VaultSlotKind.DpapiUser && machineKey is null)
        {
            return new VaultRecoveryResult(
                VaultRecoveryOutcome.ChannelMissing,
                null,
                "当前用户无法读取本机解锁密钥。");
        }

        foreach (var slot in candidates)
        {
            byte[]? dek = slotKind == VaultSlotKind.DpapiUser
                ? slot.TryUnwrapMachine(machineKey!)
                : slot.TryUnwrapSecret(secret.Span);

            if (dek is null)
            {
                continue;
            }

            try
            {
                header.VerifyMac(dek);
                return new VaultRecoveryResult(
                    VaultRecoveryOutcome.Success,
                    slot.Id,
                    $"{DisplayName(channel)}通道验证成功。");
            }
            finally
            {
                Array.Clear(dek);
            }
        }

        return new VaultRecoveryResult(
            VaultRecoveryOutcome.WrongKey,
            null,
            $"{DisplayName(channel)}通道存在，但输入不正确。");
    }

    private VaultRecoveryResult TryLegacy(string vaultPath, VaultRecoveryChannelType channel, Secret secret)
    {
        if (channel != VaultRecoveryChannelType.RecoveryCode)
        {
            return new VaultRecoveryResult(
                VaultRecoveryOutcome.ChannelMissing,
                null,
                "v2 容器不支持该恢复通道。");
        }

        var info = _vault.ReadHeaderInfo(vaultPath);
        if (!info.HasRecovery)
        {
            return new VaultRecoveryResult(
                VaultRecoveryOutcome.ChannelMissing,
                null,
                "容器中没有恢复码通道。");
        }

        return _vault.TryVerify(vaultPath, secret.Span)
            ? new VaultRecoveryResult(VaultRecoveryOutcome.Success, null, "恢复码验证成功。")
            : new VaultRecoveryResult(VaultRecoveryOutcome.WrongKey, null, "恢复码通道存在，但输入不正确。");
    }

    private static void AddMissingPlaceholders(List<VaultRecoveryChannel> channels)
    {
        if (!channels.Any(channel => channel.Type == VaultRecoveryChannelType.RecoveryCode))
        {
            channels.Add(new VaultRecoveryChannel(
                VaultRecoveryChannelType.RecoveryCode,
                null,
                "恢复码",
                false,
                "容器中没有恢复码通道"));
        }

        if (!channels.Any(channel => channel.Type == VaultRecoveryChannelType.EmergencyPassword))
        {
            channels.Add(new VaultRecoveryChannel(
                VaultRecoveryChannelType.EmergencyPassword,
                null,
                "应急密码",
                false,
                "未设置应急密码"));
        }

        if (!channels.Any(channel => channel.Type == VaultRecoveryChannelType.DpapiUser))
        {
            channels.Add(new VaultRecoveryChannel(
                VaultRecoveryChannelType.DpapiUser,
                null,
                "本机自动解锁",
                false,
                "未开启本机自动解锁"));
        }
    }

    private static string DisplayName(VaultRecoveryChannelType channel) => channel switch
    {
        VaultRecoveryChannelType.RecoveryCode => "恢复码",
        VaultRecoveryChannelType.EmergencyPassword => "应急密码",
        VaultRecoveryChannelType.DpapiUser => "本机自动解锁",
        _ => "恢复套件",
    };

    private static byte ReadVersion(string vaultPath)
    {
        using var input = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (VaultHeaderV3.IsV3(input))
        {
            return VaultHeaderV3.FormatVersion;
        }

        Span<byte> head = stackalloc byte[7];
        try
        {
            input.ReadExactly(head);
        }
        catch (EndOfStreamException ex)
        {
            throw new VaultException("Vault 文件损坏或长度不足。", ex);
        }

        if (!head[..6].SequenceEqual("FLVLT1"u8))
        {
            throw new VaultException("不是有效的 FolderLock Vault 文件。");
        }

        return head[6];
    }
}
