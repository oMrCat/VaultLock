namespace FolderLock.Core.Data;

using FolderLock.Core.Security;

public enum EncryptionMode
{
    None = 0,
    Aes256Gcm = 1,
}

public sealed class FolderRecord
{
    public long Id { get; set; }

    public required string Path { get; set; }

    public required string DisplayName { get; set; }

    public string? PasswordHash { get; set; }

    public bool IsLocked { get; set; }

    public string? DaclSddl { get; set; }

    public bool AccessRulesProtected { get; set; }

    /// <summary>加锁前目录的 Owner SID，用于解锁失败时给出恢复指引。</summary>
    public string? OwnerSid { get; set; }

    /// <summary>加锁前目录的原始属性（uint 形式），解锁时只还原 Hidden/System 两位。</summary>
    public uint? OriginalAttributes { get; set; }

    public EncryptionMode EncryptionMode { get; set; } = EncryptionMode.None;

    public string? RecoveryHash { get; set; }

    public string? ProtectedRecoveryCode { get; set; }

    public string? VaultPath { get; set; }

    /// <summary>DPAPI（CurrentUser）保护的密码提示，仅存数据库，不进入容器头部。</summary>
    public string? PasswordHintProtected { get; set; }

    /// <summary>用户确认已备份恢复码的时间，用于 30 天提醒。</summary>
    public DateTimeOffset? RecoveryBackedUpAt { get; set; }

    public int FailedAttempts { get; set; }

    public DateTimeOffset? LockoutUntil { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastLockedAt { get; set; }
}

public enum AuditAction
{
    Add,
    Lock,
    Unlock,
    ChangePassword,
    Remove,
    FailedAttempt,
    AutoRelock,
    TraceClean,
    ExportKit,
    ImportKit,
    WatchlistSync,
    AddKeySlot,
    RemoveKeySlot,
    RotateSecret,
    RevealRecoveryCode,
    UnlockViaDpapi,
    UpgradeVault,
}

public sealed class AuditEntry
{
    public long Id { get; set; }

    public long? FolderId { get; set; }

    public string? FolderPath { get; set; }

    public required string Action { get; set; }

    public bool Success { get; set; }

    public string? Detail { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>v3 容器密钥槽在数据库中的元数据。槽标签与恢复码副本只存数据库，不进入头部。</summary>
public sealed class VaultKeySlotRecord
{
    public required Guid SlotId { get; set; }

    public long FolderId { get; set; }

    public VaultSlotKind Kind { get; set; }

    public string? Label { get; set; }

    /// <summary>DPAPI 保护的秘密副本（恢复码 / 应急密码），不存明文。</summary>
    public string? ProtectedSecret { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastRevealedAt { get; set; }
}
