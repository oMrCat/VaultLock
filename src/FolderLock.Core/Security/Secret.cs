using System.Security.Cryptography;

namespace FolderLock.Core.Security;

public sealed class Secret : IDisposable
{
    private char[]? _chars;

    public Secret(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _chars = value.ToCharArray();
    }

    public Secret(char[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _chars = (char[])value.Clone();
    }

    public Secret(ReadOnlySpan<char> value)
    {
        _chars = value.ToArray();
    }

    public ReadOnlySpan<char> Span => _chars ?? ReadOnlySpan<char>.Empty;

    public bool IsEmpty => _chars is null || _chars.Length == 0;

    public static Secret Random(int length)
    {
        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
        var chars = new char[length];
        for (var i = 0; i < length; i++)
        {
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        return new Secret(chars);
    }

    public void Dispose()
    {
        if (_chars is not null)
        {
            Array.Clear(_chars);
            _chars = null;
        }
    }
}
