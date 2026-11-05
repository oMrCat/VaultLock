using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace FolderLock.App;

public sealed class SingleInstance : IDisposable
{
    private const string MutexName = @"Local\FolderLock.SingleInstance";
    private const string PipeName = "FolderLock.CommandPipe";
    private const int MaxCommandLength = 4096;
    private const int ConnectionTimeoutSeconds = 5;
    private const int ReadTimeoutSeconds = 2;

    private static readonly HashSet<string> AllowedVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "add",
        "lock",
        "unlock",
        "remove",
        "open",
        "verify",
        "decrypt",
        "salvage",
    };

    private readonly Mutex _mutex;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    public SingleInstance()
    {
        _mutex = new Mutex(initiallyOwned: true, MutexName, out var isFirst);
        IsFirstInstance = isFirst;
    }

    public bool IsFirstInstance { get; }

    public event Action<string>? CommandReceived;

    public void StartServer()
    {
        _cts = new CancellationTokenSource();
        _ = Task.Run(() => ListenAsync(_cts.Token));
    }

    public static void Forward(string verb, string path)
    {
        if (!AllowedVerbs.Contains(verb) || string.IsNullOrWhiteSpace(path) || path.Length > MaxCommandLength)
        {
            return;
        }

        try
        {
            using var client = new NamedPipeClientStream(
                ".",
                PipeName,
                PipeDirection.Out,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            client.Connect(2000);
            using var writer = new StreamWriter(client) { AutoFlush = true };
            writer.WriteLine($"{verb}|{path}");
        }
        catch
        {
        }
    }

    private async Task ListenAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.In,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                connectCts.CancelAfter(TimeSpan.FromSeconds(ConnectionTimeoutSeconds));
                await server.WaitForConnectionAsync(connectCts.Token);

                using var reader = new StreamReader(server);
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                readCts.CancelAfter(TimeSpan.FromSeconds(ReadTimeoutSeconds));
                var line = await reader.ReadLineAsync(readCts.Token);

                if (IsValidCommand(line))
                {
                    CommandReceived?.Invoke(line!);
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                break;
            }
            catch (OperationCanceledException)
            {
                // 连接/读取超时：静默重试，避免空转。
            }
            catch
            {
                await BackoffAsync(token);
            }
        }
    }

    private static bool IsValidCommand(string? line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.Length > MaxCommandLength)
        {
            return false;
        }

        var separator = line.IndexOf('|');
        if (separator <= 0 || separator == line.Length - 1)
        {
            return false;
        }

        return AllowedVerbs.Contains(line[..separator]);
    }

    private static async Task BackoffAsync(CancellationToken token)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500), token);
        }
        catch (OperationCanceledException)
        {
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            _cts?.Cancel();
            _mutex.ReleaseMutex();
        }
        catch
        {
        }

        _mutex.Dispose();
        _cts?.Dispose();
    }
}
