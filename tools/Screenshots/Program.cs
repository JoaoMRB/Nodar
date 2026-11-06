// Gera os screenshots do README sem tocar no ecrã: a app é renderizada fora do ecrã (Avalonia headless)
// em modo demonstração (rede fictícia; os CVEs vêm da NVD real). Fundo sólido, sem dados do utilizador.
// Uso: dotnet run --project tools/Screenshots -- docs/screenshots --demo [--lang pt|en]

using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Nodar.App;
using Nodar.App.Services;
using Nodar.App.ViewModels;
using Nodar.App.Views;

if (!DemoData.IsEnabled)
{
    // O modo demonstração lê "--demo" da linha de comandos.
    Console.Error.WriteLine("Corre com: dotnet run --project tools/Screenshots -- <pasta> --demo");
    return 1;
}

var langIndex = Array.IndexOf(args, "--lang");
var lang = langIndex >= 0 && langIndex + 1 < args.Length ? args[langIndex + 1] : "pt";
var outDir = Path.GetFullPath(args.First(a => !a.StartsWith("--") && a != lang));
Directory.CreateDirectory(outDir);

AppBuilder.Configure<App>()
    .UseSkia()
    .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
    .WithInterFont()
    .SetupWithoutStarting();

var window = new MainWindow { Width = 1440, Height = 900 };
var vm = new MainViewModel(new WindowPlatformServices(window));
// Idioma pedido, aplicado diretamente: as definições do utilizador não são gravadas.
Nodar.Core.Localization.Loc.Instance.Apply(lang);
window.DataContext = vm;
window.Show();

// Fundo sólido (sem Acrylic não há nada por trás para mostrar).
if (window.FindControl<Border>("Tint") is { } tint)
    tint.Background = new SolidColorBrush(Color.Parse("#FF0B0D14"));

void Pump(TimeSpan duration)
{
    var until = DateTime.UtcNow + duration;
    while (DateTime.UtcNow < until)
    {
        Dispatcher.UIThread.RunJobs();
        Thread.Sleep(15);
    }
}

void WaitFor(Func<bool> condition, TimeSpan timeout)
{
    var until = DateTime.UtcNow + timeout;
    while (!condition() && DateTime.UtcNow < until)
        Pump(TimeSpan.FromMilliseconds(100));
}

void Save(string name)
{
    Pump(TimeSpan.FromMilliseconds(900)); // animações (painel, entradas) terminam
    var frame = window.CaptureRenderedFrame() ?? throw new InvalidOperationException("Sem frame");
    var path = Path.Combine(outDir, name);
    frame.Save(path);
    Console.WriteLine($"{name}  {frame.PixelSize.Width}×{frame.PixelSize.Height}");
}

// O primeiro scan arranca quando a janela abre (MainWindow.OnOpened).
WaitFor(() => vm.HasScanned, TimeSpan.FromSeconds(5));
if (!vm.HasScanned)
    _ = vm.StartAsync();
WaitFor(() => vm.HasScanned && !vm.IsScanning, TimeSpan.FromMinutes(3));
vm.Notifications.Items.Clear();

// 1. Dispositivos
Save("dispositivos.png");

// 2. Detalhes de um servidor com vulnerabilidades, com o painel deslocado até aos CVEs
vm.SelectedDevice = vm.Devices.First(d => d.IpAddress == "192.168.1.40");
Pump(TimeSpan.FromMilliseconds(600));
var detailsScroll = window.GetVisualDescendants().OfType<ScrollViewer>()
    .FirstOrDefault(s => s.FindAncestorOfType<Border>() is { } b && b.Classes.Contains("details"));
if (detailsScroll != null)
{
    Pump(TimeSpan.FromMilliseconds(300));
    detailsScroll.Offset = new Vector(0, 330);
}
Save("detalhes.png");

// 2b. Revisão de um dispositivo: "é meu / não reconheço", nome e nota (dados inventados da demonstração)
vm.SelectedDevice = vm.Devices.First(d => d.IpAddress == "192.168.1.95");
Pump(TimeSpan.FromMilliseconds(600));
if (detailsScroll != null)
{
    Pump(TimeSpan.FromMilliseconds(300));
    detailsScroll.Offset = new Vector(0, 0);
}
Save("revisao.png");

// 3. Segurança
vm.SelectedDevice = null;
vm.NavigateCommand.Execute(Page.Security);
// "O que a internet vê" só corre a pedido: em demonstração a resposta é inventada, nada sai do computador.
vm.Exposure.CheckInternetCommand.Execute(null);
WaitFor(() => vm.Exposure.HasInternetResult, TimeSpan.FromSeconds(5));
Save("seguranca.png");

// (Histórico fica de fora: em demonstração todos os eventos são do mesmo minuto.)

return 0;
