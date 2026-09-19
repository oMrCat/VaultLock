using System.Text;
using FolderLock.Core.Security;

namespace FolderLock.Core.Tests.Security;

public sealed class VaultEncryptorTests : IDisposable
{
    private const string Password = "vault-password";
    private const int Iterations = 1000;

    private readonly string _root;
    private readonly string _source;
    private readonly string _vault;
    private readonly string _restored;
    private readonly VaultEncryptor _encryptor = new();
    private readonly string _recoveryCode = RecoveryCode.Generate();

    public VaultEncryptorTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _source = Path.Combine(_root, "source");
        _vault = Path.Combine(_root, "source" + VaultEncryptor.Extension);
        _restored = Path.Combine(_root, "restored");
        BuildTree(_source);
    }

    [Fact]
    public void EncryptThenDecrypt_RoundTripsTree()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        Assert.True(File.Exists(_vault));
        Assert.False(File.Exists(_vault + ".tmp"));

        _encryptor.DecryptToDirectory(_vault, _restored, Password);

        AssertTreesEqual(_source, _restored);
    }

    [Fact]
    public void Encrypt_LeavesSourceUntouched()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        Assert.True(File.Exists(Path.Combine(_source, "a.txt")));
    }

    [Fact]
    public void Decrypt_WithRecoveryCodeWorks()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        _encryptor.DecryptToDirectory(_vault, _restored, _recoveryCode);

        AssertTreesEqual(_source, _restored);
    }

    [Fact]
    public void Decrypt_WithNormalizedRecoveryCodeWorks()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);
        var messy = _recoveryCode.Replace("-", " ").ToLowerInvariant();

        _encryptor.DecryptToDirectory(_vault, _restored, messy);

        AssertTreesEqual(_source, _restored);
    }

    [Fact]
    public void Decrypt_WithoutRecoveryStillWorks()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, recoveryCode: null, Iterations);

        _encryptor.DecryptToDirectory(_vault, _restored, Password);

        AssertTreesEqual(_source, _restored);
    }

    [Fact]
    public void Decrypt_WithWrongSecretThrows()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        Assert.Throws<VaultException>(() => _encryptor.DecryptToDirectory(_vault, _restored, "wrong-secret"));
    }

    [Fact]
    public void Verify_DoesNotWriteAndDetectsCorruption()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        _encryptor.Verify(_vault, Password);
        Assert.False(Directory.Exists(_restored));

        var bytes = File.ReadAllBytes(_vault);
        bytes[200] ^= 0xFF;
        File.WriteAllBytes(_vault, bytes);

        Assert.Throws<VaultException>(() => _encryptor.Verify(_vault, Password));
    }

    [Fact]
    public void Decrypt_RejectsNonVaultFile()
    {
        var bogus = Path.Combine(_root, "bogus.flvault");
        File.WriteAllText(bogus, "not a vault");

        Assert.Throws<VaultException>(() => _encryptor.DecryptToDirectory(bogus, _restored, Password));
    }

    [Fact]
    public void Encrypt_ReportsProgressToCompletion()
    {
        var progress = new ProgressCollector();

        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations, progress);

        Assert.NotEmpty(progress.Values);
        var last = progress.Values[^1];
        Assert.True(last.Total > 0);
        Assert.Equal(last.Total, last.Processed);
    }

    [Fact]
    public void Decrypt_ReportsProgress()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);
        var progress = new ProgressCollector();

        _encryptor.DecryptToDirectory(_vault, _restored, Password, progress);

        Assert.NotEmpty(progress.Values);
        Assert.Equal(progress.Values[^1].Total, progress.Values[^1].Processed);
    }

    [Fact]
    public void Encrypt_PreCancelledThrowsAndLeavesNothing()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations, null, cts.Token));

        Assert.False(File.Exists(_vault));
        Assert.False(File.Exists(_vault + ".tmp"));
    }

    [Fact]
    public void Encrypt_CancelledMidwayRemovesTemp()
    {
        using var cts = new CancellationTokenSource();
        var progress = new ActionProgress(value =>
        {
            if (value.Processed > 0)
            {
                cts.Cancel();
            }
        });

        Assert.ThrowsAny<OperationCanceledException>(() =>
            _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations, progress, cts.Token));

        Assert.False(File.Exists(_vault));
        Assert.False(File.Exists(_vault + ".tmp"));
    }

    [Fact]
    public void CompressedVault_RoundTripsAndIsSmaller()
    {
        var compressible = Path.Combine(_root, "compressible");
        Directory.CreateDirectory(compressible);
        File.WriteAllBytes(Path.Combine(compressible, "data.txt"), System.Text.Encoding.ASCII.GetBytes(new string('A', 500_000)));

        var plainVault = Path.Combine(_root, "plain.flvault");
        var zipVault = Path.Combine(_root, "zip.flvault");

        _encryptor.EncryptDirectory(compressible, plainVault, Password, null, Iterations, null, default, compress: false);
        _encryptor.EncryptDirectory(compressible, zipVault, Password, null, Iterations, null, default, compress: true);

        Assert.True(_encryptor.ReadHeaderInfo(zipVault).IsCompressed);
        Assert.False(_encryptor.ReadHeaderInfo(plainVault).IsCompressed);
        Assert.True(new FileInfo(zipVault).Length < new FileInfo(plainVault).Length);

        var restored = Path.Combine(_root, "restored-zip");
        _encryptor.DecryptToDirectory(zipVault, restored, Password.AsSpan());

        Assert.Equal(
            File.ReadAllBytes(Path.Combine(compressible, "data.txt")),
            File.ReadAllBytes(Path.Combine(restored, "data.txt")));
    }

    [Fact]
    public void ReadHeaderInfo_ReportsMetadata()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        var info = _encryptor.ReadHeaderInfo(_vault);

        Assert.True(info.HasRecovery);
        Assert.Equal(Iterations, info.Iterations);
        Assert.True(info.Size > 0);
    }

    [Fact]
    public void TryVerify_TrueForCorrectFalseForWrong()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        Assert.True(_encryptor.TryVerify(_vault, Password.AsSpan()));
        Assert.False(_encryptor.TryVerify(_vault, "wrong".AsSpan()));
    }

    [Fact]
    public void Salvage_ReportsFailureOnCorruption()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);
        var bytes = File.ReadAllBytes(_vault);
        bytes[200] ^= 0xFF;
        File.WriteAllBytes(_vault, bytes);

        var result = _encryptor.SalvageToDirectory(_vault, _restored, Password.AsSpan());

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Salvage_SucceedsOnHealthyVault()
    {
        _encryptor.EncryptDirectory(_source, _vault, Password, _recoveryCode, Iterations);

        var result = _encryptor.SalvageToDirectory(_vault, _restored, Password.AsSpan());

        Assert.True(result.Success);
        AssertTreesEqual(_source, _restored);
    }

    private sealed class ProgressCollector : IProgress<VaultProgress>
    {
        public List<VaultProgress> Values { get; } = new();

        public void Report(VaultProgress value) => Values.Add(value);
    }

    private sealed class ActionProgress : IProgress<VaultProgress>
    {
        private readonly Action<VaultProgress> _action;

        public ActionProgress(Action<VaultProgress> action) => _action = action;

        public void Report(VaultProgress value) => _action(value);
    }

    private static void BuildTree(string root)
    {
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "a.txt"), "hello world");
        Directory.CreateDirectory(Path.Combine(root, "empty"));

        var sub = Path.Combine(root, "sub");
        Directory.CreateDirectory(sub);
        var big = new byte[200_000];
        Random.Shared.NextBytes(big);
        File.WriteAllBytes(Path.Combine(sub, "b.bin"), big);

        var deeper = Path.Combine(sub, "deeper");
        Directory.CreateDirectory(deeper);
        File.WriteAllText(Path.Combine(deeper, "c.txt"), "deep content");
    }

    private static void AssertTreesEqual(string expectedRoot, string actualRoot)
    {
        var expected = Snapshot(expectedRoot);
        var actual = Snapshot(actualRoot);

        Assert.Equal(expected.Keys.OrderBy(k => k, StringComparer.Ordinal), actual.Keys.OrderBy(k => k, StringComparer.Ordinal));
        foreach (var (key, value) in expected)
        {
            Assert.True(actual.TryGetValue(key, out var other), $"Missing {key}");
            Assert.Equal(value, other);
        }
    }

    private static Dictionary<string, string?> Snapshot(string root)
    {
        var result = new Dictionary<string, string?>(StringComparer.Ordinal);
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));

        foreach (var dir in Directory.EnumerateDirectories(full, "*", SearchOption.AllDirectories))
        {
            result[Path.GetRelativePath(full, dir).Replace('\\', '/') + "/"] = null;
        }

        foreach (var file in Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(full, file).Replace('\\', '/');
            if (Path.GetFileName(file) == "b.bin")
            {
                result[relative] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file)));
            }
            else
            {
                result[relative] = File.ReadAllText(file);
            }
        }

        return result;
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
