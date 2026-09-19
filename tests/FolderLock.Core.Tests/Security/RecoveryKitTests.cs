using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class RecoveryKitTests : IDisposable
{
    private readonly string _root;
    private readonly string _kit;

    public RecoveryKitTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _kit = Path.Combine(_root, "backup" + RecoveryKit.Extension);
    }

    private static List<RecoveryKitEntry> Sample() => new()
    {
        new RecoveryKitEntry
        {
            Path = @"C:\Data\One",
            DisplayName = "One",
            PasswordHash = "PBKDF2-SHA256$1000$c2FsdA==$aGFzaA==",
            RecoveryCode = "ABCD-EFGH-JKLM-NPQR",
            EncryptionMode = 1,
            IsLocked = true,
            VaultPath = @"C:\Data\One.flvault",
        },
        new RecoveryKitEntry { Path = @"C:\Data\Two", DisplayName = "Two" },
    };

    [Fact]
    public void ExportImportRoundTrips()
    {
        RecoveryKit.Export(_kit, "kit-pass".AsSpan(), Sample(), iterations: 1000);

        Assert.True(File.Exists(_kit));

        var loaded = RecoveryKit.Import(_kit, "kit-pass".AsSpan());

        Assert.Equal(2, loaded.Count);
        Assert.Equal(@"C:\Data\One", loaded[0].Path);
        Assert.Equal("ABCD-EFGH-JKLM-NPQR", loaded[0].RecoveryCode);
        Assert.Equal(1, loaded[0].EncryptionMode);
    }

    [Fact]
    public void ImportWithWrongPassphraseThrows()
    {
        RecoveryKit.Export(_kit, "right".AsSpan(), Sample(), iterations: 1000);

        Assert.Throws<VaultException>(() => RecoveryKit.Import(_kit, "wrong".AsSpan()));
    }

    [Fact]
    public void ImportRejectsNonKitFile()
    {
        var bogus = Path.Combine(_root, "bogus.flkit");
        File.WriteAllText(bogus, "not a kit");

        Assert.Throws<VaultException>(() => RecoveryKit.Import(bogus, "x".AsSpan()));
    }

    [Fact]
    public void TamperedKitFailsAuthentication()
    {
        RecoveryKit.Export(_kit, "kit-pass".AsSpan(), Sample(), iterations: 1000);
        var bytes = File.ReadAllBytes(_kit);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(_kit, bytes);

        Assert.Throws<VaultException>(() => RecoveryKit.Import(_kit, "kit-pass".AsSpan()));
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
