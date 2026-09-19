using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public class SecretTests
{
    [Fact]
    public void SecretExposesValueWhileAlive()
    {
        using var secret = new Secret("hunter2");

        Assert.False(secret.IsEmpty);
        Assert.Equal("hunter2", secret.Span.ToString());
    }

    [Fact]
    public void SecretIsClearedOnDispose()
    {
        var secret = new Secret("hunter2");
        secret.Dispose();

        Assert.True(secret.IsEmpty);
        Assert.True(secret.Span.IsEmpty);
    }

    [Fact]
    public void SecretDoesNotAliasSourceArray()
    {
        var source = "abc".ToCharArray();
        using var secret = new Secret(source);

        source[0] = 'z';

        Assert.Equal("abc", secret.Span.ToString());
    }

    [Fact]
    public void SpanHashingMatchesStringHashing()
    {
        using var secret = new Secret("same-password");
        var fromSpan = PasswordHasher.Hash(secret.Span, iterations: 1000);
        var fromString = PasswordHasher.Hash("same-password", iterations: 1000);

        Assert.True(PasswordHasher.Verify("same-password", fromSpan));
        Assert.True(PasswordHasher.Verify(secret.Span, fromString));
    }

    [Fact]
    public void RandomSecretsDiffer()
    {
        using var a = Secret.Random(24);
        using var b = Secret.Random(24);

        Assert.Equal(24, a.Span.Length);
        Assert.NotEqual(a.Span.ToString(), b.Span.ToString());
    }
}
