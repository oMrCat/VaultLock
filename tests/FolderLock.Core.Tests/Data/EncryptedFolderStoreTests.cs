using System.Text;
using FolderLock.Core.Data;

namespace FolderLock.Core.Tests.Data;

public sealed class EncryptedFolderStoreTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private readonly byte[] _key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    public EncryptedFolderStoreTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _dbPath = Path.Combine(_root, "locked.db");
    }

    [Fact]
    public void SqlCipherProviderIsActive()
    {
        Assert.False(string.IsNullOrWhiteSpace(FolderStore.GetCipherVersion()));
    }

    [Fact]
    public void EncryptedRoundTrip()
    {
        var store = new FolderStore(_dbPath, _key);
        store.Initialize();
        store.Insert(new FolderRecord { Path = @"C:\Secret\Vault", DisplayName = "Vault" });

        var reopened = new FolderStore(_dbPath, _key);
        reopened.Initialize();

        Assert.Single(reopened.GetAll());
    }

    [Fact]
    public void DatabaseFileDoesNotLeakPlaintext()
    {
        var store = new FolderStore(_dbPath, _key);
        store.Initialize();
        store.Insert(new FolderRecord { Path = @"C:\TopSecret\Hidden", DisplayName = "HiddenName", PasswordHash = "markerhash" });

        var text = Encoding.ASCII.GetString(File.ReadAllBytes(_dbPath));

        Assert.DoesNotContain("TopSecret", text);
        Assert.DoesNotContain("HiddenName", text);
        Assert.DoesNotContain("markerhash", text);
    }

    [Fact]
    public void WrongKeyCannotOpen()
    {
        var store = new FolderStore(_dbPath, _key);
        store.Initialize();
        store.Insert(new FolderRecord { Path = @"C:\Secret", DisplayName = "Secret" });

        var wrong = new FolderStore(_dbPath, new byte[32]);
        Assert.ThrowsAny<Exception>(() => wrong.Initialize());
    }

    [Fact]
    public void MigratesPlaintextDatabase()
    {
        var plain = new FolderStore(_dbPath);
        plain.Initialize();
        plain.Insert(new FolderRecord { Path = @"C:\Data\One", DisplayName = "One" });

        var encrypted = new FolderStore(_dbPath, _key);
        encrypted.Initialize();

        Assert.Single(encrypted.GetAll());
        Assert.False(File.Exists(_dbPath + ".plain"));

        var text = Encoding.ASCII.GetString(File.ReadAllBytes(_dbPath));
        Assert.DoesNotContain(@"C:\Data\One", text);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }
}
