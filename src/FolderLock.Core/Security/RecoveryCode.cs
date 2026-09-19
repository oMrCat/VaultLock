using System.Security.Cryptography;
using System.Text;

namespace FolderLock.Core.Security;

public static class RecoveryCode
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public const int DefaultBytes = 20;

    public static string Generate(int byteCount = DefaultBytes)
    {
        if (byteCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount));
        }

        return Encode(RandomNumberGenerator.GetBytes(byteCount));
    }

    public static string Normalize(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return Normalize(input.AsSpan());
    }

    public static string Normalize(ReadOnlySpan<char> input)
    {
        var builder = new StringBuilder(input.Length);
        foreach (var raw in input)
        {
            var upper = char.ToUpperInvariant(raw);
            var ch = upper switch
            {
                'I' or 'L' => '1',
                'O' => '0',
                _ => upper,
            };

            if (Alphabet.IndexOf(ch) >= 0)
            {
                builder.Append(ch);
            }
        }

        return builder.ToString();
    }

    public static byte[] NormalizeToBytes(string input) => Encoding.UTF8.GetBytes(Normalize(input));

    private static string Encode(ReadOnlySpan<byte> data)
    {
        var builder = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bitsLeft += 8;

            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                builder.Append(Alphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }

        if (bitsLeft > 0)
        {
            builder.Append(Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }

        return Format(builder.ToString());
    }

    private static string Format(string raw)
    {
        var builder = new StringBuilder(raw.Length + raw.Length / 4);
        for (var i = 0; i < raw.Length; i++)
        {
            if (i > 0 && i % 4 == 0)
            {
                builder.Append('-');
            }

            builder.Append(raw[i]);
        }

        return builder.ToString();
    }
}
