using System.IO;
using System.Security.Cryptography;

namespace FolderLock.App;

public static class DatabaseKeyStore
{
    private static string KeyFilePath =>
        Path.Combine(FolderLock.Core.Data.AppPaths.DataDirectory, "db.key");

    public static byte[] GetOrCreate()
    {
        try
        {
            if (File.Exists(KeyFilePath))
            {
                var protectedBytes = Convert.FromBase64String(File.ReadAllText(KeyFilePath));
                var key = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
                if (key.Length >= 32)
                {
                    return key;
                }
            }
        }
        catch
        {
        }

        var newKey = RandomNumberGenerator.GetBytes(32);

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(KeyFilePath)!);
            var protectedBytes = ProtectedData.Protect(newKey, optionalEntropy: null, DataProtectionScope.CurrentUser);
            File.WriteAllText(KeyFilePath, Convert.ToBase64String(protectedBytes));
        }
        catch
        {
        }

        return newKey;
    }
}
