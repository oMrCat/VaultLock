namespace FolderLock.Core.Security;

public sealed class Keyring : IDisposable
{
    private readonly Dictionary<long, Secret> _secrets = new();

    public int Count => _secrets.Count;

    public void Store(long id, Secret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        if (_secrets.Remove(id, out var existing))
        {
            existing.Dispose();
        }

        _secrets[id] = new Secret(secret.Span);
    }

    public bool TryGet(long id, out Secret secret) => _secrets.TryGetValue(id, out secret!);

    public bool Contains(long id) => _secrets.ContainsKey(id);

    public void Remove(long id)
    {
        if (_secrets.Remove(id, out var secret))
        {
            secret.Dispose();
        }
    }

    public void Clear()
    {
        foreach (var secret in _secrets.Values)
        {
            secret.Dispose();
        }

        _secrets.Clear();
    }

    public void Dispose()
    {
        Clear();
    }
}
