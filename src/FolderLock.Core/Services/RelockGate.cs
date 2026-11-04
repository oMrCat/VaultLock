namespace FolderLock.Core.Services;

/// <summary>同一文件夹的自动重锁只允许一个在途操作；空闲全量锁定同样 single-flight。</summary>
public sealed class RelockGate
{
    private readonly object _sync = new();
    private readonly HashSet<long> _pending = new();
    private bool _global;

    public bool TryEnter(long id)
    {
        lock (_sync)
        {
            return _pending.Add(id);
        }
    }

    public void Exit(long id)
    {
        lock (_sync)
        {
            _pending.Remove(id);
        }
    }

    public bool TryEnterGlobal()
    {
        lock (_sync)
        {
            if (_global)
            {
                return false;
            }

            _global = true;
            return true;
        }
    }

    public void ExitGlobal()
    {
        lock (_sync)
        {
            _global = false;
        }
    }
}
