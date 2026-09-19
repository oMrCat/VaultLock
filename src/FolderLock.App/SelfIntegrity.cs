using System.IO;
using System.Security.Cryptography;

namespace FolderLock.App;

public static class SelfIntegrity
{
    public static bool Ensure()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
            {
                return true;
            }

            using var stream = File.OpenRead(exe);
            var hash = Convert.ToHexString(SHA256.HashData(stream));

            var settings = AppSettings.Current;
            if (string.IsNullOrEmpty(settings.ExecutableHash))
            {
                settings.ExecutableHash = hash;
                settings.Save();
                return true;
            }

            return string.Equals(settings.ExecutableHash, hash, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return true;
        }
    }
}
