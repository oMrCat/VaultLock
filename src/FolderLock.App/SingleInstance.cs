using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace FolderLock.App;

public sealed class SingleInstance : IDisposable
{
    private const string MutexName = @"Local\FolderLock.SingleInstance";
    private const string PipeName = "FolderLock.CommandPipe";

    private readonly Mutex _mutex;
    private CancellationTokenSource? _cts;

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
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
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
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(token);

                using var reader = new StreamReader(server);
                var line = await reader.ReadLineAsync(token);
                if (!string.IsNullOrWhiteSpace(line))
                {
                    CommandReceived?.Invoke(line!);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
            }
        }
    }

    public void Dispose()
    {
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
