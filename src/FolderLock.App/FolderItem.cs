using System.Globalization;
using FolderLock.Core.Data;

namespace FolderLock.App;

public sealed class FolderItem
{
    public FolderItem(FolderRecord record)
    {
        Record = record;
    }

    public FolderRecord Record { get; }

    public long Id => Record.Id;

    public string DisplayName => Record.DisplayName;

    public string Path => Record.Path;

    public bool IsLocked => Record.IsLocked;

    public bool IsEncrypted => Record.EncryptionMode == EncryptionMode.Aes256Gcm;

    public string StatusText => Record.IsLocked ? L.T("Status.Locked") : L.T("Status.Unlocked");

    public string ModeText => IsEncrypted ? L.T("Mode.Aes") : L.T("Mode.Acl");

    public string LastLockedText => Record.LastLockedAt is { } value
        ? value.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture)
        : "—";
}
