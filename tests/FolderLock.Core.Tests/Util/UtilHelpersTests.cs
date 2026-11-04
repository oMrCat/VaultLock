using FolderLock.Core.Util;

namespace FolderLock.Core.Tests.Util;

public sealed class UtilHelpersTests : IDisposable
{
    private readonly string _root;

    public UtilHelpersTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [Fact]
    public void CsvSanitizer_NeutralisesFormulaInjectionAndEscapesQuotes()
    {
        Assert.Equal("'=SUM(A1)", CsvSanitizer.Escape("=SUM(A1)"));
        Assert.Equal("'+1", CsvSanitizer.Escape("+1"));
        Assert.Equal("'-1", CsvSanitizer.Escape("-1"));
        Assert.Equal("'@cmd", CsvSanitizer.Escape("@cmd"));
        Assert.Equal("\"a,b\"", CsvSanitizer.Escape("a,b"));
        Assert.Equal("\"he said \"\"hi\"\"\"", CsvSanitizer.Escape("he said \"hi\""));
        Assert.Equal(string.Empty, CsvSanitizer.Escape(null));
    }

    [Fact]
    public void AtomicFile_ReplacesContentWithoutLeavingTempFiles()
    {
        var path = Path.Combine(_root, "settings.json");

        AtomicFile.WriteAllText(path, "first");
        Assert.Equal("first", File.ReadAllText(path));

        AtomicFile.WriteAllText(path, "second");
        Assert.Equal("second", File.ReadAllText(path));
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    [Fact]
    public void RelockGate_AllowsOnlyOneFlightPerFolderAndGlobally()
    {
        var gate = new FolderLock.Core.Services.RelockGate();

        Assert.True(gate.TryEnter(1));
        Assert.False(gate.TryEnter(1));
        gate.Exit(1);
        Assert.True(gate.TryEnter(1));
        gate.Exit(1);

        Assert.True(gate.TryEnterGlobal());
        Assert.False(gate.TryEnterGlobal());
        gate.ExitGlobal();
        Assert.True(gate.TryEnterGlobal());
        gate.ExitGlobal();
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
