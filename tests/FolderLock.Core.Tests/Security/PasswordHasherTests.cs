using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public class PasswordHasherTests
{
    private const string Password = "correct horse battery staple";

    [Fact]
    public void Hash_UsesRandomSalt()
    {
        var first = PasswordHasher.Hash(Password, iterations: 1000);
        var second = PasswordHasher.Hash(Password, iterations: 1000);

        Assert.NotEqual(first.Salt, second.Salt);
        Assert.NotEqual(first.Hash, second.Hash);
    }

    [Fact]
    public void Hash_ProducesExpectedSizes()
    {
        var result = PasswordHasher.Hash(Password, iterations: 1000);

        Assert.Equal(PasswordHasher.SaltSize, result.Salt.Length);
        Assert.Equal(PasswordHasher.HashSize, result.Hash.Length);
        Assert.Equal(1000, result.Iterations);
        Assert.Equal(PasswordHasher.AlgorithmName, result.Algorithm);
    }

    [Fact]
    public void Verify_ReturnsTrueForCorrectPassword()
    {
        var stored = PasswordHasher.Hash(Password, iterations: 1000);

        Assert.True(PasswordHasher.Verify(Password, stored));
    }

    [Theory]
    [InlineData("")]
    [InlineData("wrong")]
    [InlineData("Correct horse battery staple")]
    public void Verify_ReturnsFalseForWrongPassword(string candidate)
    {
        var stored = PasswordHasher.Hash(Password, iterations: 1000);

        Assert.False(PasswordHasher.Verify(candidate, stored));
    }

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        var original = PasswordHasher.Hash(Password, iterations: 1234);

        var decoded = PasswordHash.Decode(original.Encode());

        Assert.Equal(original.Algorithm, decoded.Algorithm);
        Assert.Equal(original.Iterations, decoded.Iterations);
        Assert.Equal(original.Salt, decoded.Salt);
        Assert.Equal(original.Hash, decoded.Hash);
        Assert.True(PasswordHasher.Verify(Password, decoded));
    }

    [Theory]
    [InlineData("")]
    [InlineData("only$two")]
    [InlineData("PBKDF2-SHA256$notanumber$c2FsdA==$aGFzaA==")]
    [InlineData("PBKDF2-SHA256$1000$not-base64$aGFzaA==")]
    public void Decode_ThrowsOnMalformedInput(string encoded)
    {
        Assert.ThrowsAny<Exception>(() => PasswordHash.Decode(encoded));
    }

    [Fact]
    public void Decode_PreservesCustomIterations()
    {
        var stored = PasswordHasher.Hash(Password, iterations: 4321);
        var decoded = PasswordHash.Decode(stored.Encode());

        Assert.Equal(4321, decoded.Iterations);
    }

    [Fact]
    public void DeriveKey_Returns32BytesAndIsDeterministic()
    {
        var salt = new byte[PasswordHasher.SaltSize];
        salt[0] = 42;

        var first = PasswordHasher.DeriveKey(Password, salt, iterations: 1000);
        var second = PasswordHasher.DeriveKey(Password, salt, iterations: 1000);

        Assert.Equal(PasswordHasher.KeySize, first.Length);
        Assert.Equal(first, second);
    }

    [Fact]
    public void DeriveKey_DiffersBySalt()
    {
        var saltA = new byte[PasswordHasher.SaltSize];
        var saltB = new byte[PasswordHasher.SaltSize];
        saltB[0] = 1;

        var keyA = PasswordHasher.DeriveKey(Password, saltA, iterations: 1000);
        var keyB = PasswordHasher.DeriveKey(Password, saltB, iterations: 1000);

        Assert.NotEqual(keyA, keyB);
    }

    [Fact]
    public void DeriveKey_RejectsShortSalt()
    {
        Assert.Throws<ArgumentException>(() => PasswordHasher.DeriveKey(Password, new byte[4]));
    }

    [Fact]
    public void Hash_RejectsNonPositiveIterations()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordHasher.Hash(Password, iterations: 0));
    }
}
