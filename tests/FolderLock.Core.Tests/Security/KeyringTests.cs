using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public class KeyringTests
{
    [Fact]
    public void StoreAndRetrieve()
    {
        using var keyring = new Keyring();
        using var secret = new Secret("pw");

        keyring.Store(1, secret);

        Assert.True(keyring.TryGet(1, out var stored));
        Assert.Equal("pw", stored.Span.ToString());
        Assert.Equal(1, keyring.Count);
    }

    [Fact]
    public void StoreDoesNotAliasSource()
    {
        using var keyring = new Keyring();
        var secret = new Secret("pw");
        keyring.Store(1, secret);

        secret.Dispose();

        Assert.True(keyring.TryGet(1, out var stored));
        Assert.Equal("pw", stored.Span.ToString());
    }

    [Fact]
    public void StoreReplacesExistingValue()
    {
        using var keyring = new Keyring();
        using var first = new Secret("one");
        using var second = new Secret("two");

        keyring.Store(1, first);
        keyring.Store(1, second);

        Assert.True(keyring.TryGet(1, out var stored));
        Assert.Equal("two", stored.Span.ToString());
        Assert.Equal(1, keyring.Count);
    }

    [Fact]
    public void RemoveDropsEntry()
    {
        using var keyring = new Keyring();
        using var secret = new Secret("pw");
        keyring.Store(1, secret);

        keyring.Remove(1);

        Assert.False(keyring.TryGet(1, out _));
        Assert.Equal(0, keyring.Count);
    }

    [Fact]
    public void ClearEmptiesKeyring()
    {
        using var keyring = new Keyring();
        using var a = new Secret("a");
        using var b = new Secret("b");
        keyring.Store(1, a);
        keyring.Store(2, b);

        keyring.Clear();

        Assert.Equal(0, keyring.Count);
        Assert.False(keyring.Contains(1));
    }
}
