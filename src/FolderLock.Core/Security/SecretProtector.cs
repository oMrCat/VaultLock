using System.Security.Cryptography;
using System.Text;

namespace FolderLock.Core.Security;

public static class SecretProtector
{
    public static string Protect(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        var bytes = Encoding.UTF8.GetBytes(secret);
        var protectedBytes = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        Array.Clear(bytes);
        return Convert.ToBase64String(protectedBytes);
    }

    public static string? Unprotect(string protectedBase64)
    {
        if (string.IsNullOrWhiteSpace(protectedBase64))
        {
            return null;
        }

        try
        {
            var protectedBytes = Convert.FromBase64String(protectedBase64);
            var bytes = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
            try
            {
                return Encoding.UTF8.GetString(bytes);
            }
            finally
            {
                Array.Clear(bytes);
            }
        }
        catch
        {
            return null;
        }
    }
}
