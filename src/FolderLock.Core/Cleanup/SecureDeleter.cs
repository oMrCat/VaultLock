using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace FolderLock.Core.Cleanup;

public sealed class SecureDeleter
{
    private const int BufferSize = 1024 * 1024;

    private readonly int _randomPasses;

    public SecureDeleter(int randomPasses = 1)
    {
        _randomPasses = Math.Max(1, randomPasses);
    }

    /// <summary>
    /// 擦除单个文件。符号链接只删除链接本身；硬链接（NumberOfLinks &gt; 1）不覆写内容，
    /// 因为覆写会同时破坏其他链接指向的数据，只删除当前目录项。
    /// </summary>
    public void DeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            File.Delete(path);
            return;
        }

        File.SetAttributes(path, FileAttributes.Normal);

        if (HasMultipleHardLinks(path))
        {
            File.Delete(path);
            return;
        }

        var length = new FileInfo(path).Length;

        using (var stream = new FileStream(
                   path,
                   FileMode.Open,
                   FileAccess.Write,
                   FileShare.None,
                   BufferSize,
                   FileOptions.WriteThrough))
        {
            var buffer = new byte[BufferSize];

            for (var pass = 0; pass < _randomPasses; pass++)
            {
                stream.Position = 0;
                long remaining = length;
                while (remaining > 0)
                {
                    var count = (int)Math.Min(buffer.Length, remaining);
                    RandomNumberGenerator.Fill(buffer.AsSpan(0, count));
                    stream.Write(buffer, 0, count);
                    remaining -= count;
                }

                stream.Flush(flushToDisk: true);
            }

            stream.Position = 0;
            Array.Clear(buffer);
            long remainingZero = length;
            while (remainingZero > 0)
            {
                var count = (int)Math.Min(buffer.Length, remainingZero);
                stream.Write(buffer, 0, count);
                remainingZero -= count;
            }

            stream.Flush(flushToDisk: true);
            stream.SetLength(0);
            stream.Flush(flushToDisk: true);
        }

        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory))
        {
            File.Delete(path);
            return;
        }

        var scrambled = Path.Combine(directory, Guid.NewGuid().ToString("N"));
        try
        {
            File.Move(path, scrambled);
            File.SetAttributes(scrambled, FileAttributes.Normal);
        }
        catch
        {
            scrambled = path;
        }

        File.Delete(scrambled);
    }

    /// <summary>
    /// 递归删除目录；不跟随 reparse point（目录联接/符号链接），遇到时只删除链接本身。
    /// 子项删除失败会先继续处理其余项，最后聚合抛错，避免“静默半删除”。
    /// </summary>
    public void DeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        var failures = new List<Exception>();
        DeleteDirectoryContents(path, failures);

        try
        {
            Directory.Delete(path, recursive: false);
        }
        catch (Exception ex)
        {
            failures.Add(ex);
        }

        if (failures.Count > 0)
        {
            throw new AggregateException($"安全擦除 {path} 时有 {failures.Count} 项失败。", failures);
        }
    }

    private void DeleteDirectoryContents(string path, List<Exception> failures)
    {
        if (new DirectoryInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return;
        }

        foreach (var entry in Directory.EnumerateFileSystemEntries(path))
        {
            try
            {
                var info = new DirectoryInfo(entry);

                if (info.Attributes.HasFlag(FileAttributes.Directory))
                {
                    if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        // 目录联接/符号链接：只删除链接，不进入目标。
                        Directory.Delete(entry, recursive: false);
                        continue;
                    }

                    DeleteDirectoryContents(entry, failures);

                    try
                    {
                        Directory.Delete(entry, recursive: false);
                    }
                    catch (Exception ex)
                    {
                        failures.Add(ex);
                    }

                    continue;
                }

                DeleteFile(entry);
            }
            catch (Exception ex)
            {
                failures.Add(ex);
            }
        }
    }

    private static bool HasMultipleHardLinks(string path)
    {
        try
        {
            using var handle = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (!GetFileInformationByHandle(handle.SafeFileHandle, out var info))
            {
                return false;
            }

            return info.NumberOfLinks > 1;
        }
        catch
        {
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileCreationTime CreationTime;
        public FileCreationTime LastAccessTime;
        public FileCreationTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileCreationTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out ByHandleFileInformation information);
}
