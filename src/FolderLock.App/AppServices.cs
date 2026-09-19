using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;

namespace FolderLock.App;

public static class AppServices
{
    public static FolderService Folders { get; } = Create();

    public static FolderLock.Core.Security.Keyring Keyring { get; } = new();

    private static FolderService Create()
    {
        var service = new FolderService(new FolderStore(key: DatabaseKeyStore.GetOrCreate()), new FolderLocker());
        try
        {
            service.SyncLockStates();
        }
        catch
        {
        }

        return service;
    }
}
