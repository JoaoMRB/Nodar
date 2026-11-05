using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using Nodar.App.Services;
using Nodar.App.ViewModels;
using Nodar.App.Views;
using Nodar.Core.Localization;
using Nodar.Core.Models;

namespace Nodar.App.Tests;

public class FilterTests
{
    private static DeviceInfo Dev(string ip, string type, string host = "", bool vulnerable = false, string mac = "") => new()
    {
        IpAddress = ip,
        MacAddress = mac.Length > 0 ? mac : $"AA:BB:CC:00:00:{int.Parse(ip.Split('.')[3]):X2}",
        Hostname = host,
        DeviceType = type,
        Vendor = "Teste",
        Vulnerabilities = vulnerable ? [new VulnerabilityInfo { CVE = "CVE-2024-0001", Severity = "High" }] : []
    };

    private static MainViewModel CreateWithDevices()
    {
        var window = new MainWindow();
        var vm = new MainViewModel(new WindowPlatformServices(window));
        window.Show();          // antes do DataContext: não arranca o scan
        window.DataContext = vm;

        // Dados isolados por teste (o tracker grava o histórico na pasta da variável NODAR_DATA_DIR).
        vm.ShowScanResultForTests(new ScanResult
        {
            Devices =
            [
                Dev("192.168.1.10", "Computador", "portatil-ana"),
                Dev("192.168.1.11", "Telemóvel", "galaxy-rui"),
                Dev("192.168.1.12", "Apple", "iphone-ana"),
                Dev("192.168.1.13", "TV", "tv-sala"),
                Dev("192.168.1.14", "Servidor", "homelab", vulnerable: true),
                Dev("192.168.1.15", "Dispositivo"),
            ]
        });
        Dispatcher.UIThread.RunJobs();
        return vm;
    }

    private static int Count(MainViewModel vm, string key) => vm.FilterChips.Single(c => c.Key == key).Count;

    [AvaloniaFact]
    public void Chips_show_only_present_groups_with_counts()
    {
        var vm = CreateWithDevices();
        var keys = vm.FilterChips.Select(c => c.Key).ToList();

        Assert.Equal("all", keys[0]);
        Assert.Equal(6, Count(vm, "all"));
        Assert.Equal(1, Count(vm, "computers"));
        Assert.Equal(2, Count(vm, "phones"));      // Telemóvel + iPhone (tipo "Apple")
        Assert.Equal(1, Count(vm, "tv"));
        Assert.Equal(1, Count(vm, "servers"));
        Assert.Equal(1, Count(vm, "other"));
        Assert.Equal(1, Count(vm, "vulnerable"));
        Assert.DoesNotContain("printers", keys);   // não há impressoras: não aparece
        Assert.DoesNotContain("watched", keys);    // ainda não há vigiados
        Assert.True(vm.HasFilterChips);
    }

    [AvaloniaFact]
    public void Selecting_a_chip_filters_and_combines_with_search()
    {
        var vm = CreateWithDevices();

        vm.SelectFilterCommand.Execute("phones");
        Assert.Equal(2, vm.Devices.Count);
        Assert.All(vm.Devices, d => Assert.Equal("phones", d.Group));
        Assert.True(vm.FilterChips.Single(c => c.Key == "phones").IsSelected);

        vm.SearchText = "galaxy";
        Assert.Equal("galaxy-rui", Assert.Single(vm.Devices).DisplayName);

        vm.SearchText = "";
        vm.SelectFilterCommand.Execute("vulnerable");
        Assert.Equal("homelab", Assert.Single(vm.Devices).DisplayName);
    }

    [AvaloniaFact]
    public void Tapping_the_active_chip_again_shows_everything()
    {
        var vm = CreateWithDevices();
        vm.SelectFilterCommand.Execute("tv");
        Assert.Single(vm.Devices);
        vm.SelectFilterCommand.Execute("tv");
        Assert.Equal("all", vm.SelectedFilter);
        Assert.Equal(6, vm.Devices.Count);
    }

    [AvaloniaFact]
    public void Watching_a_device_updates_the_watched_chip()
    {
        var vm = CreateWithDevices();
        var tv = vm.Devices.Single(d => d.Group == "tv");

        vm.ToggleWatchCommand.Execute(tv);
        Assert.Equal(1, Count(vm, "watched"));
        vm.SelectFilterCommand.Execute("watched");
        Assert.Same(tv, Assert.Single(vm.Devices));

        vm.ToggleWatchCommand.Execute(tv);       // deixar de vigiar
        Assert.DoesNotContain(vm.FilterChips, c => c.Key == "watched");
        Assert.Equal("all", vm.SelectedFilter);  // o filtro deixou de existir: volta a "Todos"
    }

    [AvaloniaFact]
    public void Every_chip_has_a_translation()
    {
        foreach (var key in DeviceFilters.TypeGroups.Concat(DeviceFilters.StateFilters).Append(DeviceFilters.All))
            Assert.True(Loc.Instance.Has("filter." + key), $"falta filter.{key}");
    }
}
