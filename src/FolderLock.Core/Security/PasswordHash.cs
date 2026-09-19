using System.Globalization;

namespace FolderLock.Core.Security;

public sealed record PasswordHash
{
    public required byte[] Salt { get; init; }

    public required byte[] Hash { get; init; }

    public int Iterations { get; init; } = PasswordHasher.DefaultIterations;

    public string Algorithm { get; init; } = PasswordHasher.AlgorithmName;

    public string Encode()
    {
        return string.Join(
            '$',
            Algorithm,
            Iterations.ToString(CultureInfo.InvariantCulture),
            Convert.ToBase64String(Salt),
            Convert.ToBase64String(Hash));
    }

    public static PasswordHash Decode(string encoded)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(encoded);

        var parts = encoded.Split('$');
        if (parts.Length != 4)
        {
            throw new FormatException("Invalid password hash format.");
        }

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations) ||
            iterations <= 0)
        {
            throw new FormatException("Invalid iteration count in password hash.");
        }

        byte[] salt;
        byte[] hash;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            hash = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Invalid base64 payload in password hash.", ex);
        }

        if (salt.Length == 0 || hash.Length == 0)
        {
            throw new FormatException("Password hash contains empty salt or hash.");
        }

        return new PasswordHash
        {
            Algorithm = parts[0],
            Iterations = iterations,
            Salt = salt,
            Hash = hash,
        };
    }
}
