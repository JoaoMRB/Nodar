using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Nodar.App.Services;
using Nodar.App.ViewModels;
using Nodar.App.Views;
using Nodar.Core.Localization;

[assembly: AvaloniaTestApplication(typeof(Nodar.App.Tests.TestApp))]

namespace Nodar.App.Tests;

public static class TestApp
{
    /// <summary>Antes de qualquer teste: dados numa pasta temporária, nunca os do utilizador.</summary>
    [System.Runtime.CompilerServices.ModuleInitializer]
    public static void IsolateUserData() =>
        Environment.SetEnvironmentVariable(Nodar.Core.NodarPaths.EnvironmentVariable,
            Path.Combine(Path.GetTempPath(), "nodar-ui-tests-" + Environment.ProcessId));

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UseSkia().UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
}

/// <summary>
/// Regressão: escolher outro idioma na caixa de seleção bloqueava a app (ciclo pt↔en com centenas de mudanças
/// por segundo), porque a lista de opções era recriada e a seleção ficava vazia por momentos.
/// </summary>
public class LanguageSwitchTests
{
    private static (MainWindow Window, MainViewModel Vm, ComboBox Combo) Create()
    {
        var window = new MainWindow();
        var vm = new MainViewModel(new WindowPlatformServices(window));
        // Mostrar antes de ligar o ViewModel: a janela só inicia o scan ao abrir se já tiver um ViewModel,
        // e um teste não deve analisar a rede de quem o corre.
        window.Show();
        window.DataContext = vm;

        // A mesma ligação que está no painel de opções (o painel em si só existe quando é aberto).
        var combo = new ComboBox();
        combo.Bind(ItemsControl.ItemsSourceProperty, new Binding("Settings.LanguageOptions") { Source = vm });
        combo.Bind(SelectingItemsControl.SelectedItemProperty, new Binding("Settings.SelectedLanguage") { Source = vm, Mode = BindingMode.TwoWay });
        var host = window.GetVisualDescendants().OfType<Panel>().First();
        host.Children.Add(combo);
        Dispatcher.UIThread.RunJobs();
        return (window, vm, combo);
    }

    private static void Pump(int ms = 200)
    {
        var until = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < until)
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(5);
        }
    }

    [AvaloniaFact]
    public void Choosing_languages_changes_language_at_most_once_each_time()
    {
        var (_, vm, combo) = Create();
        var original = vm.Settings.SelectedLanguage;
        var changes = 0;
        void Count() => changes++;
        Loc.Instance.LanguageChanged += Count;
        try
        {
            foreach (var code in new[] { "en", "pt", "en", "auto", "en", "pt" })
            {
                var before = changes;
                combo.SelectedItem = vm.Settings.LanguageOptions.First(o => o.Code == code);
                Pump();
                Assert.InRange(changes - before, 0, 1);
                Assert.Equal(code, vm.Settings.SelectedLanguage?.Code);
                Assert.Equal(code == "auto" ? Loc.SystemLanguage() : code, Loc.Instance.Language);
            }
        }
        finally
        {
            Loc.Instance.LanguageChanged -= Count;
            vm.Settings.SelectedLanguage = original ?? vm.Settings.LanguageOptions[0];
            Pump();
        }
    }

    [AvaloniaFact]
    public void Xaml_texts_follow_the_language()
    {
        var (window, vm, combo) = Create();
        var original = vm.Settings.SelectedLanguage;
        try
        {
            combo.SelectedItem = vm.Settings.LanguageOptions.First(o => o.Code == "en");
            Pump();
            var texts = window.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text).ToList();
            Assert.Contains("Local network", texts);   // {l:T brand.subtitle}
            Assert.Contains("Security", texts);        // navegação

            combo.SelectedItem = vm.Settings.LanguageOptions.First(o => o.Code == "pt");
            Pump();
            texts = window.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text).ToList();
            Assert.Contains("Rede local", texts);
            Assert.Contains("Segurança", texts);
        }
        finally
        {
            vm.Settings.SelectedLanguage = original ?? vm.Settings.LanguageOptions[0];
            Pump();
        }
    }

    [AvaloniaFact]
    public void Options_keep_identity_and_auto_shows_the_system_language()
    {
        var (_, vm, combo) = Create();
        var original = vm.Settings.SelectedLanguage;
        var optionsBefore = vm.Settings.LanguageOptions;
        try
        {
            combo.SelectedItem = vm.Settings.LanguageOptions.First(o => o.Code == "en");
            Pump();
            Assert.Same(optionsBefore, vm.Settings.LanguageOptions); // a lista não é recriada
            var system = Loc.SystemLanguage() == "pt" ? "Português" : "English";
            Assert.Contains(system, vm.Settings.LanguageOptions.First(o => o.Code == "auto").Label);
        }
        finally
        {
            vm.Settings.SelectedLanguage = original ?? vm.Settings.LanguageOptions[0];
            Pump();
        }
    }
}
