using Avalonia.Headless.XUnit;
using Nodar.App.ViewModels;
using Nodar.Core.Settings;

namespace Nodar.App.Tests;

/// <summary>Os view-models filhos do <see cref="MainViewModel"/>: preferências, avisos e vistas.</summary>
public class ViewModelTests
{
    // ---------------------------------------------------------------- Preferências

    [AvaloniaFact]
    public void Scan_options_keep_their_dependencies()
    {
        var s = FilterTests.CreateWithDevices().Settings;
        var (ports, services, vulns) = (s.PortScan, s.ServiceDetection, s.VulnerabilityScan);
        try
        {
            s.PortScan = false;
            Assert.False(s.ServiceDetection);
            Assert.False(s.VulnerabilityScan);

            s.VulnerabilityScan = true;            // vulnerabilidades ⇒ serviços ⇒ portas
            Assert.True(s.ServiceDetection);
            Assert.True(s.PortScan);

            s.ServiceDetection = false;            // sem serviços não há vulnerabilidades
            Assert.False(s.VulnerabilityScan);
            Assert.True(s.PortScan);
        }
        finally
        {
            s.PortScan = ports;
            s.ServiceDetection = services;
            s.VulnerabilityScan = vulns;
        }
    }

    [AvaloniaFact]
    public void Preferences_are_saved_when_they_change()
    {
        var s = FilterTests.CreateWithDevices().Settings;
        var original = s.DeepScan;
        try
        {
            s.DeepScan = !original;
            Assert.Equal(!original, AppSettings.Load().DeepScan);
        }
        finally
        {
            s.DeepScan = original;
        }
        Assert.Equal(original, AppSettings.Load().DeepScan);
    }

    [AvaloniaFact]
    public void Settings_announce_what_the_rest_of_the_app_must_redo()
    {
        var s = FilterTests.CreateWithDevices().Settings;
        var (offline, auto, interval) = (s.ShowOffline, s.AutoRefresh, s.SelectedInterval);
        int offlineEvents = 0, scheduleEvents = 0;
        s.ShowOfflineChanged += () => offlineEvents++;
        s.RefreshScheduleChanged += () => scheduleEvents++;
        try
        {
            s.ShowOffline = !offline;
            Assert.Equal(1, offlineEvents);
            Assert.Equal(0, scheduleEvents);

            s.AutoRefresh = !auto;
            Assert.Equal(1, scheduleEvents);

            s.SelectedInterval = s.IntervalOptions.First(o => o.Seconds == 300);
            Assert.Equal(2, scheduleEvents);
            Assert.Equal(TimeSpan.FromMinutes(5), s.RefreshInterval);
        }
        finally
        {
            s.ShowOffline = offline;
            s.AutoRefresh = auto;
            s.SelectedInterval = interval;
        }
    }

    // ---------------------------------------------------------------- Avisos

    [AvaloniaFact]
    public void Toasts_are_capped_and_can_be_dismissed()
    {
        var host = new ToastHost();
        for (var i = 0; i < 6; i++)
            host.Show($"aviso {i}", "", ToastKind.Info);

        Assert.Equal(4, host.Items.Count);
        Assert.Equal("aviso 2", host.Items[0].Title); // os mais antigos saem primeiro

        host.DismissCommand.Execute(host.Items[0]);
        Assert.Equal(3, host.Items.Count);
        host.DismissCommand.Execute(null);             // sem aviso: não faz nada
        Assert.Equal(3, host.Items.Count);
    }

    // ---------------------------------------------------------------- Vistas

    [AvaloniaFact]
    public void Security_lists_the_vulnerabilities_of_online_devices()
    {
        var vm = FilterTests.CreateWithDevices();

        Assert.Equal("CVE-2024-0001", Assert.Single(vm.Security.AllVulnerabilities).Cve);
        Assert.True(vm.Security.HasVulnerabilityData);
        Assert.Equal(1, vm.Security.HighCount);
        Assert.Equal(0, vm.Security.CriticalCount);
        Assert.Equal(0, vm.Security.MediumLowCount);
        Assert.False(vm.Security.ShowAllClear);
    }

    [AvaloniaFact]
    public void History_knows_every_device_seen()
    {
        var vm = FilterTests.CreateWithDevices();

        Assert.True(vm.History.KnownDevices.Count >= 6);
        Assert.True(vm.History.HasHistory);
        Assert.All(vm.History.RecentEvents, e => Assert.False(string.IsNullOrEmpty(e.DeviceName)));
    }

    [AvaloniaFact]
    public void Removing_a_watch_from_the_watchlist_updates_the_list_and_the_filter()
    {
        var vm = FilterTests.CreateWithDevices();
        var tv = vm.Devices.Single(d => d.Group == "tv");

        vm.ToggleWatchCommand.Execute(tv);
        var item = Assert.Single(vm.Watchlist.Items);
        Assert.True(vm.Watchlist.HasItems);
        Assert.Contains(vm.FilterChips, c => c.Key == "watched");

        vm.RemoveWatchCommand.Execute(item);

        Assert.Empty(vm.Watchlist.Items);
        Assert.False(vm.Watchlist.HasItems);
        Assert.False(tv.IsWatched);
        Assert.DoesNotContain(vm.FilterChips, c => c.Key == "watched"); // a pílula não fica com a contagem antiga
    }
}
