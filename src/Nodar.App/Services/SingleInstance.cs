namespace Nodar.App.Services;

/// <summary>
/// Uma só instância por utilizador: abrir o Nodar outra vez traz a janela existente para a frente,
/// em vez de criar um segundo ícone na bandeja e um segundo scan.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    private readonly Mutex _mutex;
    private readonly EventWaitHandle _showSignal;
    private readonly bool _owned;
    private readonly CancellationTokenSource _stop = new();

    private SingleInstance(string name)
    {
        _mutex = new Mutex(initiallyOwned: true, $@"Local\{name}.Instance", out _owned);
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, $@"Local\{name}.Show");
    }

    public bool IsFirst => _owned;

    /// <param name="demo">O modo demonstração pode correr ao lado da instância normal.</param>
    public static SingleInstance Acquire(bool demo) => new(demo ? "Nodar.Demo" : "Nodar");

    /// <summary>Pede à instância que já está a correr para se mostrar.</summary>
    public void SignalFirstInstance() => _showSignal.Set();

    /// <summary>Na primeira instância: chama <paramref name="onShow"/> sempre que outra instância for aberta.</summary>
    public void ListenForOtherInstances(Action onShow)
    {
        var thread = new Thread(() =>
        {
            var handles = new[] { _showSignal, _stop.Token.WaitHandle };
            while (WaitHandle.WaitAny(handles) == 0)
                onShow();
        }) { IsBackground = true, Name = "Nodar.SingleInstance" };
        thread.Start();
    }

    public void Dispose()
    {
        _stop.Cancel();
        if (_owned)
            _mutex.ReleaseMutex();
        _mutex.Dispose();
        _showSignal.Dispose();
    }
}
