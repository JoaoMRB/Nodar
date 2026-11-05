using Avalonia;
using Nodar.App.Services;

namespace Nodar.App;

internal static class Program
{
    /// <summary>Instância única (criada antes do Avalonia; usada pela App para mostrar a janela).</summary>
    internal static SingleInstance? Instance { get; private set; }

    [STAThread]
    public static int Main(string[] args)
    {
        using var instance = SingleInstance.Acquire(DemoData.IsEnabled);
        if (!instance.IsFirst)
        {
            // Já há um Nodar a correr (talvez minimizado na bandeja): trazê-lo para a frente.
            instance.SignalFirstInstance();
            return 0;
        }

        Instance = instance;
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
