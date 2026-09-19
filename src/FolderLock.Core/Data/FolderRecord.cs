namespace FolderLock.Core.Data;

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

    public EncryptionMode EncryptionMode { get; set; } = EncryptionMode.None;

    public string? RecoveryHash { get; set; }

    public string? ProtectedRecoveryCode { get; set; }

    public string? VaultPath { get; set; }

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
