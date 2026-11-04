using System.IO;
using System.Security.Cryptography;
using FolderLock.Core.Security;

namespace FolderLock.App;

public static class DatabaseKeyStore
{
    private static string KeyFilePath =>
        Path.Combine(FolderLock.Core.Data.AppPaths.DataDirectory, "db.key");

    public static byte[] GetOrCreate()
    {
        return KeyFileStore.GetOrCreate(
            KeyFilePath,
            bytes => ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser),
            bytes => ProtectedData.Unprotect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser));
    }
}
