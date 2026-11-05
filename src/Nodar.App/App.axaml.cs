using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Nodar.App.ViewModels;
using Nodar.App.Views;

namespace Nodar.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = new MainWindow();
            var viewModel = new MainViewModel(new Services.WindowPlatformServices(window));
            window.DataContext = viewModel;
            desktop.MainWindow = window;

            // Um erro na interface não deve fechar a app: fica registado e é mostrado como aviso.
            Avalonia.Threading.Dispatcher.UIThread.UnhandledException += (_, e) =>
            {
                Services.CrashLog.Write(e.Exception, "Erro na interface");
                viewModel.ReportUnexpectedError(e.Exception);
                e.Handled = true;
            };
            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                Services.CrashLog.Write(e.Exception, "Tarefa em segundo plano");
                e.SetObserved();
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
