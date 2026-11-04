using System.Diagnostics;
using System.Runtime.InteropServices;
using FolderLock.Core.Cleanup;

namespace FolderLock.Core.Tests.Cleanup;

public sealed class SecureDeleterLinkTests : IDisposable
{
    private readonly string _root;
    private readonly SecureDeleter _deleter = new();

    public SecureDeleterLinkTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    [Fact]
    public void DeleteFile_HardLinkIsUnlinkedWithoutDestroyingOtherLink()
    {
        var original = Path.Combine(_root, "original.txt");
        var link = Path.Combine(_root, "link.txt");
        File.WriteAllText(original, "shared-content");

        Assert.True(CreateHardLinkW(link, original, IntPtr.Zero), "无法创建硬链接，测试环境不支持该探测。");

        _deleter.DeleteFile(original);

        Assert.False(File.Exists(original));
        Assert.True(File.Exists(link));
        Assert.Equal("shared-content", File.ReadAllText(link));
    }

    [Fact]
    public void DeleteDirectory_DoesNotFollowJunctions()
    {
        var outside = Path.Combine(Path.GetTempPath(), "FolderLockTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outside);
        var payload = Path.Combine(outside, "keep.txt");
        File.WriteAllText(payload, "keep");

        var container = Path.Combine(_root, "container");
        Directory.CreateDirectory(container);
        var junction = Path.Combine(container, "junction");

        try
        {
            Assert.True(CreateJunction(junction, outside), "无法创建目录联接，测试环境不支持该探测。");

            _deleter.DeleteDirectory(container);

            Assert.False(Directory.Exists(container));
            Assert.True(Directory.Exists(outside));
            Assert.True(File.Exists(payload));
            Assert.Equal("keep", File.ReadAllText(payload));
        }
        finally
        {
            TryDelete(outside);
        }
    }

    [Fact]
    public void DeleteDirectory_ShredsRegularFilesAndRemovesTree()
    {
        var container = Path.Combine(_root, "regular");
        Directory.CreateDirectory(container);
        File.WriteAllText(Path.Combine(container, "a.txt"), "aaa");
        Directory.CreateDirectory(Path.Combine(container, "sub"));
        File.WriteAllText(Path.Combine(container, "sub", "b.txt"), "bbb");

        _deleter.DeleteDirectory(container);

        Assert.False(Directory.Exists(container));
    }

    private static bool CreateJunction(string link, string target)
    {
        try
        {
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c mklink /J \"{link}\" \"{target}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            process?.WaitForExit(5000);
            return process is not null && process.ExitCode == 0 && Directory.Exists(link);
        }
        catch
        {
            return false;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
        }
    }

    public void Dispose() => TryDelete(_root);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateHardLinkW(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes);
}
