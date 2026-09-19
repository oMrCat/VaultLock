using FolderLock.Core.Data;
using FolderLock.Core.Security;
using FolderLock.Core.Services;

namespace FolderLock.Core.Tests.Services;

public sealed class FolderServiceSecurityTests : IDisposable
{
    private const string Password = "correct-password";

    private readonly string _root;
    private readonly string _folder;
    private readonly FolderService _service;

    public FolderServiceSecurityTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        _folder = Path.Combine(_root, "Vault");
        Directory.CreateDirectory(_folder);
        File.WriteAllText(Path.Combine(_folder, "a.txt"), "x");

        _service = new FolderService(new FolderStore(Path.Combine(_root, "db.sqlite")), new FolderLocker());
    }

    [Fact]
    public void RepeatedWrongPasswordsTriggerLockout()
    {
        var record = _service.Add(_folder, Password);

        for (var i = 0; i < 5; i++)
        {
            Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, "wrong"));
        }

        var stored = _service.GetAll().Single();
        Assert.True(stored.FailedAttempts >= 5);
        Assert.NotNull(stored.LockoutUntil);

        var ex = Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, Password));
        Assert.Contains("重试", ex.Message);
    }

    [Fact]
    public void SuccessfulLoginResetsFailureCounter()
    {
        var record = _service.Add(_folder, Password);
        Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, "wrong"));

        Assert.Equal(1, _service.GetAll().Single().FailedAttempts);

        _service.Lock(record.Id, Password);

        Assert.Equal(0, _service.GetAll().Single().FailedAttempts);
    }

    [Fact]
    public void ActionsAreAudited()
    {
        var record = _service.Add(_folder, Password);
        _service.Lock(record.Id, Password);
        _service.Unlock(record.Id, Password);

        var audit = _service.GetAudit();

        Assert.Contains(audit, a => a.Action == "Add");
        Assert.Contains(audit, a => a.Action == "Lock" && a.Success);
        Assert.Contains(audit, a => a.Action == "Unlock" && a.Success);
    }

    [Fact]
    public void FailedAttemptsAreAudited()
    {
        var record = _service.Add(_folder, Password);
        Assert.Throws<FolderLockException>(() => _service.Lock(record.Id, "wrong"));

        Assert.Contains(_service.GetAudit(), a => a.Action == "FailedAttempt" && !a.Success);
    }

    [Fact]
    public void ClearAuditEmptiesLog()
    {
        _service.Add(_folder, Password);

        _service.ClearAudit();

        Assert.Empty(_service.GetAudit());
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
