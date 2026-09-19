using System.Security.Cryptography;

namespace FolderLock.Core.Security;

public static class PasswordHasher
{
    public const string AlgorithmName = "PBKDF2-SHA256";

    public const int DefaultIterations = 210_000;

    public const int SaltSize = 16;

    public const int HashSize = 32;

    public const int KeySize = 32;

    public static PasswordHash Hash(ReadOnlySpan<char> password, int iterations = DefaultIterations)
    {
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be positive.");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Derive(password, salt, iterations, HashSize);

        return new PasswordHash
        {
            Salt = salt,
            Hash = hash,
            Iterations = iterations,
        };
    }

    public static bool Verify(ReadOnlySpan<char> password, PasswordHash stored)
    {
        ArgumentNullException.ThrowIfNull(stored);

        var computed = Derive(password, stored.Salt, stored.Iterations, stored.Hash.Length);
        return CryptographicOperations.FixedTimeEquals(computed, stored.Hash);
    }

    public static byte[] Derive(ReadOnlySpan<char> password, byte[] salt, int iterations, int outputBytes)
    {
        ArgumentNullException.ThrowIfNull(salt);
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations));
        }

        if (outputBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputBytes));
        }

        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, outputBytes);
    }

    public static byte[] DeriveKey(ReadOnlySpan<char> password, byte[] salt, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length < SaltSize)
        {
            throw new ArgumentException($"Salt must be at least {SaltSize} bytes.", nameof(salt));
        }

        return Derive(password, salt, iterations, KeySize);
    }
}
