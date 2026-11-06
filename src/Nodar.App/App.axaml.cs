using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Nodar.App.Services;
using Nodar.App.ViewModels;
using Nodar.App.Views;
using Nodar.Core.Localization;
using Nodar.Core.Settings;

namespace Nodar.App;

public partial class App : Application
{
    private WindowsTray? _tray;
    private bool _exiting;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // A app vive na bandeja: só termina quando o utilizador escolhe "Sair" (ou fecha sem bandeja).
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

            // Idioma antes de criar a janela (sem "piscar" no idioma errado).
            Loc.Instance.Apply(AppSettings.Load().Language);

            var window = new MainWindow();
            var platform = new WindowPlatformServices(window);
            var viewModel = new MainViewModel(platform);
            window.DataContext = viewModel;

            try
            {
                _tray = new WindowsTray(Loc.T("tray.tooltip"));
                Loc.Instance.LanguageChanged += () => _tray?.SetTooltip(Loc.T("tray.tooltip"));
                platform.Tray = _tray;
                _tray.OpenRequested += () => ShowWindow(window);
                _tray.ScanRequested += () => viewModel.ScanCommand.Execute(null);
                _tray.ExitRequested += () => Exit(desktop, window);
            }
            catch (Exception ex)
            {
                // Sem bandeja (ex.: sessão sem Explorador): a app funciona na mesma, sem notificações do Windows.
                CrashLog.Write(ex, "Ícone da bandeja");
            }

            window.Closing += (_, e) =>
            {
                if (_exiting)
                    return;
                if (viewModel.Settings.CloseToTray && _tray?.IsVisible == true)
                {
                    e.Cancel = true;
                    window.Hide();
                    viewModel.OnHiddenToTray();
                }
            };
            window.Closed += (_, _) => Exit(desktop, window);

            // Outra instância foi aberta: mostrar esta.
            Program.Instance?.ListenForOtherInstances(() => Dispatcher.UIThread.Post(() => ShowWindow(window)));

            var startHidden = Environment.GetCommandLineArgs().Contains(StartupRegistration.MinimizedArgument)
                              && _tray?.IsVisible == true;
            if (startHidden)
                _ = viewModel.StartAsync(); // arranque com o Windows: analisa já, sem abrir a janela
            else
                desktop.MainWindow = window;

            // Um erro na interface não deve fechar a app: fica registado e é mostrado como aviso.
            Dispatcher.UIThread.UnhandledException += (_, e) =>
            {
                CrashLog.Write(e.Exception, "Erro na interface");
                viewModel.ReportUnexpectedError(e.Exception);
                e.Handled = true;
            };
            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                CrashLog.Write(e.Exception, "Tarefa em segundo plano");
                e.SetObserved();
            };
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static void ShowWindow(Window window)
    {
        if (!window.IsVisible)
            window.Show();
        if (window.WindowState == WindowState.Minimized)
            window.WindowState = WindowState.Normal;
        window.Activate();
    }

    private void Exit(IClassicDesktopStyleApplicationLifetime desktop, Window window)
    {
        if (_exiting)
            return;
        _exiting = true;
        _tray?.Dispose();
        _tray = null;
        window.Close();
        desktop.Shutdown();
    }
}
