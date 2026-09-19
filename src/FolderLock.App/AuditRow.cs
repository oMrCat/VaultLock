using FolderLock.Core.Data;

namespace FolderLock.App;

public sealed class AuditRow
{
    public AuditRow(AuditEntry entry)
    {
        Entry = entry;
    }

    public AuditEntry Entry { get; }

    public string Time => Entry.CreatedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public string Action => Entry.Action switch
    {
        "Add" => L.T("Action.Add"),
        "Lock" => L.T("Action.Lock"),
        "Unlock" => L.T("Action.Unlock"),
        "ChangePassword" => L.T("Action.ChangePassword"),
        "Remove" => L.T("Action.Remove"),
        "FailedAttempt" => L.T("Action.FailedAttempt"),
        "AutoRelock" => L.T("Action.AutoRelock"),
        "TraceClean" => L.T("Action.TraceClean"),
        _ => Entry.Action,
    };

    public string Result => Entry.Success ? L.T("Action.Success") : L.T("Action.Failure");

    public bool Success => Entry.Success;

    public string Folder => Entry.FolderPath ?? string.Empty;

    public string Detail => Entry.Detail ?? string.Empty;
}
