using System.Security.Cryptography;

namespace FolderLock.Core.Cleanup;

public sealed class SecureDeleter
{
    private const int BufferSize = 1024 * 1024;

    private readonly int _randomPasses;

    public SecureDeleter(int randomPasses = 1)
    {
        _randomPasses = Math.Max(1, randomPasses);
    }

    public void DeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        File.SetAttributes(path, FileAttributes.Normal);
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

    public void DeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                DeleteFile(file);
            }
            catch
            {
            }
        }

        foreach (var directory in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories)
                     .OrderByDescending(d => d.Length))
        {
            try
            {
                Directory.Delete(directory, recursive: false);
            }
            catch
            {
            }
        }

        Directory.Delete(path, recursive: true);
    }
}
