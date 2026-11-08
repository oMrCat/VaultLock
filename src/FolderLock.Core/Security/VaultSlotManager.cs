namespace FolderLock.Core.Security;

/// <summary>新增或替换密钥槽时描述目标槽。</summary>
/// <param name="Kind">槽类型。</param>
/// <param name="Label">可选标签，只存数据库，不进入容器头部。</param>
/// <param name="Secret">密码类槽的秘密（主密码 / 恢复码 / 应急密码）。</param>
/// <param name="MachineKey">kdf=2 槽使用的 32 字节机器 KEK。</param>
public sealed record VaultSlotSpec(
    VaultSlotKind Kind,
    string? Label = null,
    Secret? Secret = null,
    byte[]? MachineKey = null);

/// <summary>头部中某个槽的只读信息（不含秘密）。</summary>
public sealed record VaultSlotInfo(
    Guid Id,
    VaultSlotKind Kind,
    VaultKdf Kdf,
    int Iterations,
    bool IsSupported);

/// <summary>
/// v3 容器密钥槽管理：增加、删除、替换槽以及 v2 → v3 升级。
/// 所有写操作只重写 4096 字节头部，DEK 不变，数据区字节完全不动。
/// </summary>
public sealed class VaultSlotManager
{
    private readonly VaultEncryptor _encryptor;

    public VaultSlotManager(VaultEncryptor? encryptor = null)
    {
        _encryptor = encryptor ?? new VaultEncryptor();
    }

    /// <summary>只读头部列出槽，不需要 DEK。</summary>
    public IReadOnlyList<VaultSlotInfo> ListSlots(string vaultPath)
    {
        var header = VaultHeaderV3.ReadFromFile(vaultPath);
        return header.Slots
            .Select(slot => new VaultSlotInfo(
                slot.Id,
                slot.Kind,
                slot.Kdf,
                (int)slot.Param1,
                slot.IsSupportedKind && slot.Kdf is VaultKdf.Pbkdf2 or VaultKdf.MachineKek))
            .ToList();
    }

    /// <summary>增加一个槽。existingSecret 必须是当前可用的密码类秘密。</summary>
    public VaultKeySlot AddSlot(string vaultPath, Secret existingSecret, VaultSlotSpec spec)
    {
        ArgumentNullException.ThrowIfNull(existingSecret);
        ArgumentNullException.ThrowIfNull(spec);

        VaultKeySlot? added = null;
        Mutate(vaultPath, existingSecret, (header, dek) =>
        {
            if (header.Slots.Count >= VaultHeaderV3.MaxSlots)
            {
                throw new VaultException($"密钥槽数量已达上限（{VaultHeaderV3.MaxSlots}）。");
            }

            added = CreateSlot(spec, header.Iterations, dek);
            return header.Slots.Append(added).ToList();
        });

        return added!;
    }

    /// <summary>删除一个槽。任何时候必须至少保留一个主密码槽。</summary>
    public void RemoveSlot(string vaultPath, Secret existingSecret, Guid slotId)
    {
        ArgumentNullException.ThrowIfNull(existingSecret);

        Mutate(vaultPath, existingSecret, (header, _) =>
        {
            var target = FindSlot(header, slotId);
            var remaining = header.Slots.Where(slot => slot.Id != slotId).ToList();
            if (target.Kind == VaultSlotKind.Password &&
                remaining.All(slot => slot.Kind != VaultSlotKind.Password))
            {
                throw new VaultException("必须至少保留一个主密码槽。");
            }

            if (remaining.Count == 0)
            {
                throw new VaultException("密钥槽数量必须为 1 到 8。");
            }

            return remaining;
        });
    }

    /// <summary>原地替换一个槽（换密码 / 轮换恢复码），槽 ID 保持不变。</summary>
    public VaultKeySlot ReplaceSlot(string vaultPath, Secret existingSecret, Guid slotId, VaultSlotSpec spec)
    {
        ArgumentNullException.ThrowIfNull(existingSecret);
        ArgumentNullException.ThrowIfNull(spec);

        VaultKeySlot? replaced = null;
        Mutate(vaultPath, existingSecret, (header, dek) =>
        {
            var target = FindSlot(header, slotId);
            if (target.Kind == VaultSlotKind.Password &&
                spec.Kind != VaultSlotKind.Password &&
                header.Slots.Count(slot => slot.Kind == VaultSlotKind.Password) <= 1)
            {
                throw new VaultException("必须至少保留一个主密码槽。");
            }

            replaced = CreateSlot(spec, header.Iterations, dek, slotId);
            return header.Slots
                .Select(existing => existing.Id == slotId ? replaced : existing)
                .ToList();
        });

        return replaced!;
    }

    /// <summary>把 v2 容器显式升级为 v3，保留原文件备份并复制数据区原始字节。</summary>
    public IReadOnlyList<VaultKeySlot> UpgradeToV3(string vaultPath, Secret existingSecret, bool keepBackup = true)
    {
        ArgumentNullException.ThrowIfNull(existingSecret);
        return _encryptor.UpgradeV2ToV3(vaultPath, existingSecret.Span, keepBackup);
    }

    private void Mutate(
        string vaultPath,
        Secret existingSecret,
        Func<VaultHeaderV3, byte[], List<VaultKeySlot>> change)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);

        using var file = new FileStream(vaultPath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        EnsureV3(file);

        var header = VaultHeaderV3.Read(file);
        var dek = header.TryUnwrap(existingSecret.Span, machineKey: null)
            ?? throw new VaultException("密码或恢复码不正确。");

        try
        {
            header.VerifyMac(dek);

            // 先在内存中完成全部修改，任何校验失败都不会触碰文件。
            var slots = change(header, dek);
            header.WriteNextBlock(file, slots, header.IsCompressed, dek);

            // 读回校验新块：HMAC 必须与同一 DEK 匹配，避免写入损坏后清零旧块。
            var check = VaultHeaderV3.Read(file);
            check.VerifyMac(dek);

            var expectedIds = slots.Select(slot => slot.Id).OrderBy(id => id).ToList();
            var actualIds = check.Slots.Select(slot => slot.Id).OrderBy(id => id).ToList();
            if (!expectedIds.SequenceEqual(actualIds))
            {
                throw new VaultException("Vault 头部写入校验失败，原文件保持不变。");
            }

            header.ClearInactiveBlock(file);
        }
        finally
        {
            Array.Clear(dek);
        }
    }

    private static void EnsureV3(FileStream file)
    {
        if (!VaultHeaderV3.IsV3(file))
        {
            throw new VaultException("该容器不是 v3 格式，请先显式升级后再管理密钥槽。");
        }
    }

    private static VaultKeySlot FindSlot(VaultHeaderV3 header, Guid slotId)
    {
        return header.Slots.FirstOrDefault(slot => slot.Id == slotId)
            ?? throw new VaultException("找不到指定的密钥槽。");
    }

    private static VaultKeySlot CreateSlot(
        VaultSlotSpec spec,
        int currentIterations,
        byte[] dek,
        Guid? id = null)
    {
        switch (spec.Kind)
        {
            case VaultSlotKind.Password:
            case VaultSlotKind.RecoveryCode:
            case VaultSlotKind.EmergencyPassword:
                {
                    if (spec.Secret is null || spec.Secret.IsEmpty)
                    {
                        throw new VaultException("密码类密钥槽必须提供秘密。");
                    }

                    var iterations = currentIterations is > 0 and <= VaultKeySlot.MaxIterations
                        ? currentIterations
                        : PasswordHasher.DefaultIterations;
                    return VaultKeySlot.CreateForSecret(spec.Kind, spec.Secret.Span, dek, iterations, id);
                }

            case VaultSlotKind.DpapiUser:
                {
                    if (spec.MachineKey is null)
                    {
                        throw new VaultException("本机自动解锁槽必须提供机器密钥。");
                    }

                    return VaultKeySlot.CreateForMachineKey(
                        VaultSlotKind.DpapiUser,
                        spec.MachineKey,
                        dek,
                        id);
                }

            default:
                throw new VaultException($"当前版本暂不支持该密钥槽类型：{spec.Kind}。");
        }
    }
}
