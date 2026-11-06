using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using Nodar.App.Services;
using Nodar.App.ViewModels;
using Nodar.App.Views;
using Nodar.Core;
using Nodar.Core.Localization;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;

namespace Nodar.App.Tests;

/// <summary>
/// "É meu / não reconheço", nomes e notas. Cada teste usa uma pasta de dados própria e só dados inventados: nada
/// do que se escreve aqui pode vir de uma rede real.
/// </summary>
public sealed class DeviceReviewTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-review-ui-" + Guid.NewGuid().ToString("N"));
    private readonly string? _previousDir = Environment.GetEnvironmentVariable(NodarPaths.EnvironmentVariable);

    public DeviceReviewTests()
    {
        Directory.CreateDirectory(_dir);
        Environment.SetEnvironmentVariable(NodarPaths.EnvironmentVariable, _dir);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(NodarPaths.EnvironmentVariable, _previousDir);
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* limpeza de uma pasta temporária */ }
    }

    private static DeviceInfo Dev(int n, string type = "Computador") => new()
    {
        IpAddress = $"192.168.1.{n}",
        MacAddress = $"AA:BB:CC:00:00:{n:X2}",
        Hostname = $"dispositivo-{n}",
        DeviceType = type,
        Vendor = "Teste"
    };

    private static MainViewModel Create(params DeviceInfo[] devices)
    {
        var window = new MainWindow();
        var vm = new MainViewModel(new WindowPlatformServices(window));
        window.Show();                       // antes do DataContext: não arranca o scan
        window.DataContext = vm;
        vm.Settings.WindowsNotifications = false; // nunca mostrar notificações do Windows a sério nos testes
        vm.ShowScanResultForTests(new ScanResult { Devices = [.. devices] });
        Dispatcher.UIThread.RunJobs();
        return vm;
    }

    private static DeviceItemViewModel Item(MainViewModel vm, int n) => vm.Devices.Single(d => d.IpAddress == $"192.168.1.{n}");

    // ---------------------------------------------------------------- O convite

    [AvaloniaFact]
    public void The_prompt_is_shown_until_the_user_marks_something_or_dismisses_it()
    {
        var vm = Create(Dev(10), Dev(11), Dev(12));

        Assert.True(vm.Review.ShowPrompt);
        Assert.False(vm.Review.IsActive);
        Assert.Contains("3", vm.Review.PromptText);
        Assert.Equal(0, vm.Review.UnreviewedCount);               // "por rever" só conta depois de começar a marcar
        Assert.DoesNotContain(vm.FilterChips, c => c.Key == "unreviewed");
        Assert.All(vm.Devices, d => Assert.False(d.HasTrustBadge));
    }

    [AvaloniaFact]
    public void Marking_all_as_known_activates_the_review_and_says_so()
    {
        var vm = Create(Dev(10), Dev(11), Dev(12));

        vm.Review.MarkAllKnownCommand.Execute(null);

        Assert.True(vm.Review.IsActive);
        Assert.False(vm.Review.ShowPrompt);
        Assert.Equal(0, vm.Review.UnreviewedCount);
        Assert.All(vm.Devices, d => Assert.Equal(DeviceTrust.Known, d.Trust));
        Assert.Contains(vm.Notifications.Items, t => t.Title == Loc.T("review.marked"));
    }

    [AvaloniaFact]
    public void Dismissing_the_prompt_is_remembered_after_a_restart()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.Review.DismissPromptCommand.Execute(null);
        Assert.False(vm.Review.ShowPrompt);

        var again = Create(Dev(10), Dev(11));
        Assert.False(again.Review.ShowPrompt);
        Assert.False(again.Review.IsActive); // dispensar não é marcar
    }

    // ---------------------------------------------------------------- Marcar um dispositivo

    [AvaloniaFact]
    public void Marking_one_device_makes_the_others_to_review_and_shows_a_filter_for_them()
    {
        var vm = Create(Dev(10), Dev(11), Dev(12));
        vm.SelectedDevice = Item(vm, 10);

        vm.Review.SetTrustCommand.Execute("known");

        Assert.True(vm.Review.IsActive);
        Assert.False(vm.Review.ShowPrompt);
        Assert.Equal(2, vm.Review.UnreviewedCount);
        Assert.Equal(2, vm.FilterChips.Single(c => c.Key == "unreviewed").Count);
        Assert.Equal(DeviceTrust.Known, Item(vm, 10).Trust);
        Assert.False(Item(vm, 10).HasTrustBadge);                  // um conhecido não leva etiqueta
        Assert.Equal(Loc.T("trust.unreviewed"), Item(vm, 11).TrustBadge);
        Assert.Contains("2", vm.DevicesSubtitle);                  // "2 por rever"
        Assert.True(vm.Review.IsKnown);
        Assert.Equal(10, int.Parse(vm.SelectedDevice!.IpAddress.Split('.')[3])); // o painel continua no mesmo dispositivo
    }

    [AvaloniaFact]
    public void A_suspicious_device_is_flagged_even_before_the_review_and_has_its_own_filter()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 11);

        vm.Review.SetTrustCommand.Execute("suspicious");

        Assert.Equal(1, vm.Review.SuspiciousCount);
        Assert.Equal(Loc.T("trust.suspicious"), Item(vm, 11).TrustBadge);
        Assert.Equal(1, vm.FilterChips.Single(c => c.Key == "suspicious").Count);

        vm.SelectFilterCommand.Execute("suspicious");
        Assert.Equal("dispositivo-11", Assert.Single(vm.Devices).Hostname);
    }

    [AvaloniaFact]
    public void Going_back_to_unreviewed_keeps_the_device_in_the_to_review_list()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.SetTrustCommand.Execute("known");
        vm.Review.SetTrustCommand.Execute("unreviewed");

        Assert.Equal(2, vm.Review.UnreviewedCount);
        Assert.True(vm.Review.IsUnreviewed);
    }

    [AvaloniaFact]
    public void The_choice_survives_a_restart()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.SetTrustCommand.Execute("known");
        vm.SelectedDevice = Item(vm, 11);
        vm.Review.SetTrustCommand.Execute("suspicious");

        var again = Create(Dev(10), Dev(11));

        Assert.Equal(DeviceTrust.Known, Item(again, 10).Trust);
        Assert.Equal(DeviceTrust.Suspicious, Item(again, 11).Trust);
        Assert.False(again.Review.ShowPrompt);
    }

    // ---------------------------------------------------------------- Nome e nota

    [AvaloniaFact]
    public void A_custom_name_replaces_the_automatic_one_and_can_be_removed()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 10);
        Assert.Equal("dispositivo-10", Item(vm, 10).DisplayName);

        vm.Review.EditName = "Portátil de teste";
        Assert.True(vm.Review.IsDirty);
        vm.Review.SaveDetailsCommand.Execute(null);

        Assert.Equal("Portátil de teste", Item(vm, 10).DisplayName);
        Assert.False(vm.Review.IsDirty);
        Assert.Equal("Portátil de teste", vm.SelectedDevice!.DisplayName);
        Assert.False(vm.Review.IsActive);                           // dar um nome não inicia a revisão

        vm.Review.EditName = "  ";
        vm.Review.SaveDetailsCommand.Execute(null);
        Assert.Equal("dispositivo-10", Item(vm, 10).DisplayName);   // volta ao nome automático
    }

    [AvaloniaFact]
    public void The_note_is_searchable_and_saved()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 11);
        vm.Review.EditNote = "ligado ao router da sala";
        vm.Review.SaveDetailsCommand.Execute(null);

        vm.SearchText = "router da sala";

        Assert.Equal("dispositivo-11", Assert.Single(vm.Devices).Hostname);
        Assert.Equal("ligado ao router da sala", new KnownDevices(_dir).Also(k => k.Load()).Find("AA:BB:CC:00:00:0B")!.Note);
    }

    [AvaloniaFact]
    public void Unsaved_text_is_not_lost_when_the_trust_changes()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.EditName = "A meio de escrever";

        vm.Review.SetTrustCommand.Execute("known");   // a lista é refeita, o texto fica

        Assert.Equal("A meio de escrever", vm.Review.EditName);
        Assert.True(vm.Review.IsDirty);
    }

    [AvaloniaFact]
    public void Opening_another_device_loads_its_own_name_and_note()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.EditName = "Nome A";
        vm.Review.EditNote = "Nota A";
        vm.Review.SaveDetailsCommand.Execute(null);

        vm.SelectedDevice = Item(vm, 11);
        Assert.Equal("", vm.Review.EditName);
        Assert.Equal("", vm.Review.EditNote);

        vm.SelectedDevice = Item(vm, 10);
        Assert.Equal("Nome A", vm.Review.EditName);
        Assert.Equal("Nota A", vm.Review.EditNote);
    }

    [AvaloniaFact]
    public void The_save_button_is_only_enabled_when_there_is_something_to_save()
    {
        var vm = Create(Dev(10));
        vm.SelectedDevice = Item(vm, 10);
        Assert.False(vm.Review.IsDirty);

        vm.Review.EditNote = "x";
        Assert.True(vm.Review.IsDirty);
        vm.Review.EditNote = "";
        Assert.False(vm.Review.IsDirty);
    }

    // ---------------------------------------------------------------- Avisos de dispositivos que voltam

    private static void Titles(MainViewModel vm, out List<string> titles) =>
        titles = [.. vm.Notifications.Items.Select(t => t.Title)];

    [AvaloniaFact]
    public void Known_devices_that_come_back_never_alert()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.Review.MarkAllKnownCommand.Execute(null);
        vm.Notifications.Items.Clear();

        vm.AnnounceReturned([Dev(10), Dev(11)]);

        Assert.Empty(vm.Notifications.Items);
    }

    [AvaloniaFact]
    public void Before_the_review_a_returning_device_is_silent()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.Notifications.Items.Clear();

        vm.AnnounceReturned([Dev(10)]);

        Assert.Empty(vm.Notifications.Items); // sem ter dito quais são os seus, não há "desconhecidos"
    }

    [AvaloniaFact]
    public void An_unknown_device_that_comes_back_alerts_once_the_review_has_started()
    {
        var vm = Create(Dev(10), Dev(11), Dev(12));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.SetTrustCommand.Execute("known");
        vm.Notifications.Items.Clear();

        vm.AnnounceReturned([Dev(11)]);

        var toast = Assert.Single(vm.Notifications.Items);
        Assert.Equal(Loc.T("review.unknown.back"), toast.Title);
        Assert.Contains("192.168.1.11", toast.Message);
    }

    [AvaloniaFact]
    public void Several_unknown_devices_are_grouped_in_one_alert()
    {
        var vm = Create(Dev(10), Dev(11), Dev(12), Dev(13));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.SetTrustCommand.Execute("known");
        vm.Notifications.Items.Clear();

        vm.AnnounceReturned([Dev(11), Dev(12), Dev(13)]);

        Assert.Equal(Loc.F("review.unknown.back.many", 3), Assert.Single(vm.Notifications.Items).Title);
    }

    [AvaloniaFact]
    public void A_suspicious_device_that_comes_back_always_alerts_even_before_the_review()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 11);
        vm.Review.SetTrustCommand.Execute("suspicious");
        vm.Notifications.Items.Clear();

        vm.AnnounceReturned([Dev(11)]);

        Assert.Equal(Loc.T("review.suspicious.back"), Assert.Single(vm.Notifications.Items).Title);
    }

    [AvaloniaFact]
    public void The_alert_uses_the_name_the_user_gave()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 11);
        vm.Review.EditName = "Consola de teste";
        vm.Review.SaveDetailsCommand.Execute(null);
        vm.Review.SetTrustCommand.Execute("suspicious");
        vm.Notifications.Items.Clear();

        vm.AnnounceReturned([Dev(11)]);

        Assert.Contains("Consola de teste", Assert.Single(vm.Notifications.Items).Message);
    }

    // ---------------------------------------------------------------- Idioma e história

    [AvaloniaFact]
    public void The_badge_and_prompt_follow_the_language()
    {
        var previous = Loc.Instance.Language;
        try
        {
            Loc.Instance.Language = "en";
            var vm = Create(Dev(10), Dev(11));
            var promptEn = vm.Review.PromptText;
            vm.SelectedDevice = Item(vm, 10);
            vm.Review.SetTrustCommand.Execute("known");
            var badgeEn = Item(vm, 11).TrustBadge;

            Loc.Instance.Language = "pt";
            Dispatcher.UIThread.RunJobs();

            Assert.NotEqual(badgeEn, Item(vm, 11).TrustBadge);
            Assert.Equal("Por rever", Item(vm, 11).TrustBadge);
            Assert.NotEqual(promptEn, vm.Review.PromptText);
        }
        finally
        {
            Loc.Instance.Language = previous;
        }
    }

    [AvaloniaFact]
    public void The_history_page_shows_the_custom_name()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.EditName = "Nome no histórico";
        vm.Review.SaveDetailsCommand.Execute(null);

        Assert.Contains(vm.History.KnownDevices, d => d.DisplayName == "Nome no histórico");
    }

    [AvaloniaFact]
    public void Nothing_is_written_outside_the_data_folder()
    {
        var vm = Create(Dev(10), Dev(11));
        vm.SelectedDevice = Item(vm, 10);
        vm.Review.EditName = "Nome";
        vm.Review.SaveDetailsCommand.Execute(null);
        vm.Review.MarkAllKnownCommand.Execute(null);

        Assert.True(File.Exists(Path.Combine(_dir, "known-devices.json")));
        Assert.StartsWith(Path.GetFullPath(_dir), Path.GetFullPath(Path.Combine(NodarPaths.DataDirectory, "known-devices.json")));
    }
}

internal static class TestExtensions
{
    /// <summary>Executa uma ação sobre o objeto e devolve-o (para usar numa expressão).</summary>
    public static T Also<T>(this T value, Action<T> action)
    {
        action(value);
        return value;
    }
}
