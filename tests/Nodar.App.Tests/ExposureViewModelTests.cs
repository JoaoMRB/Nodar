using Avalonia.Headless.XUnit;
using Nodar.App.ViewModels;
using Nodar.Core.Localization;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using Nodar.Core.Settings;

namespace Nodar.App.Tests;

/// <summary>A vista de exposição: portas abertas pelo router, MAC do router e o que a internet vê.</summary>
public sealed class ExposureViewModelTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-exposure-ui-" + Guid.NewGuid().ToString("N"));

    public ExposureViewModelTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* limpeza de uma pasta temporária */ }
    }

    private const string RouterMac = "D0:CF:0E:00:00:01";
    private const string OtherMac = "AA:BB:CC:00:00:09";

    private sealed class Lookup(InternetExposure answer)
    {
        public List<string?> Asked { get; } = [];
        public TaskCompletionSource? Gate { get; init; }

        public async Task<InternetExposure> Run(string? ip, CancellationToken ct)
        {
            Asked.Add(ip);
            if (Gate != null)
                await Gate.Task;
            return answer;
        }
    }

    private ExposureViewModel Create(Lookup? lookup = null)
    {
        var guard = new GatewayGuard(_dir);
        guard.Load();
        var mappings = new PortMappingTracker(_dir);
        mappings.Load();
        return new ExposureViewModel(guard, mappings, (lookup ?? new Lookup(Ok())).Run);
    }

    private static InternetExposure Ok(params int[] ports) =>
        new() { Status = InternetCheckStatus.Ok, Ip = "203.0.113.7", Ports = [.. ports], Vulns = ["CVE-2018-15473"] };

    private static DeviceInfo Device(string ip, string mac, string host) => new() { IpAddress = ip, MacAddress = mac, Hostname = host };

    private static DeviceItemViewModel Item(DeviceInfo d) => new(d, null, d.MacAddress, isGateway: false, isOnline: true, isWatched: false);

    private static readonly DeviceInfo Router = Device("192.168.1.1", RouterMac, "router");
    private static readonly DeviceInfo Homelab = Device("192.168.1.40", "DC:A6:32:7B:00:12", "homelab");
    private static readonly DeviceInfo Ps5 = Device("192.168.1.95", "7C:BB:8A:99:00:11", "ps5");

    private static PortMapping Map(int external, string client, int? internalPort = null, string protocol = "TCP", string description = "") =>
        new() { Protocol = protocol, ExternalPort = external, InternalClient = client, InternalPort = internalPort ?? external, Description = description };

    private static ScanResult Scan(UpnpReport? upnp, params DeviceInfo[] devices) => new()
    {
        Network = new LocalNetworkInfo { IpAddress = "192.168.1.23", Gateway = "192.168.1.1" },
        Devices = [Router, .. devices],
        Upnp = upnp
    };

    private static UpnpReport Report(params PortMapping[] mappings) =>
        new() { Status = UpnpStatus.Ok, ExternalIp = "203.0.113.7", Mappings = [.. mappings] };

    private static IReadOnlyList<DeviceItemViewModel> Items(params DeviceInfo[] devices) => [.. devices.Select(Item)];

    // ---------------------------------------------------------------- Portas abertas pelo router

    [AvaloniaFact]
    public void Mappings_are_matched_to_devices_and_sensitive_ones_come_first()
    {
        var vm = Create();
        var result = Scan(Report(Map(3074, "192.168.1.95", protocol: "UDP", description: "PlayStation"), Map(22, "192.168.1.40")), Homelab, Ps5);
        vm.ApplyScan(result);
        vm.Update(Items(Router, Homelab, Ps5));

        Assert.True(vm.ShowUpnp);
        Assert.True(vm.HasPortMappings);
        Assert.Equal(2, vm.PortMappings.Count);

        var ssh = vm.PortMappings[0];                       // o sensível vem primeiro
        Assert.Equal("TCP 22", ssh.External);
        Assert.True(ssh.IsSensitive);
        Assert.Contains("homelab", ssh.Target);
        Assert.Contains("192.168.1.40:22", ssh.Target);

        var console = vm.PortMappings[1];
        Assert.Equal("PlayStation", console.Purpose);       // a descrição dada pela aplicação que pediu a porta
        Assert.False(console.IsSensitive);

        Assert.True(vm.NeedsAttention);
        Assert.Contains("203.0.113.7", vm.UpnpExternal);
    }

    [AvaloniaFact]
    public void A_mapping_to_an_unknown_machine_still_shows_its_address_and_no_description_falls_back_to_the_port_name()
    {
        var vm = Create();
        vm.ApplyScan(Scan(Report(Map(8080, "192.168.1.200", internalPort: 80))));
        vm.Update(Items(Router));

        var item = Assert.Single(vm.PortMappings);
        Assert.Equal("192.168.1.200:80", item.Target);
        Assert.Equal("HTTP", item.Purpose);
    }

    [AvaloniaFact]
    public void A_mapping_with_a_lease_is_marked_as_temporary()
    {
        var vm = Create();
        var parsec = new PortMapping
            { Protocol = "UDP", ExternalPort = 22810, InternalClient = "192.168.1.95", InternalPort = 22810, Description = "Parsec", LeaseSeconds = 2556 };
        vm.ApplyScan(Scan(Report(parsec, Map(8443, "192.168.1.40")), Homelab, Ps5));
        vm.Update(Items(Router, Homelab, Ps5));

        Assert.Contains(Loc.T("upnp.temporary"), vm.PortMappings.Single(m => m.Purpose == "Parsec").Since);
        Assert.DoesNotContain(Loc.T("upnp.temporary"), vm.PortMappings.Single(m => m.Purpose != "Parsec").Since);
    }

    [AvaloniaFact]
    public void A_router_without_upnp_is_good_news_and_needs_no_attention()
    {
        var vm = Create();
        vm.ApplyScan(Scan(new UpnpReport { Status = UpnpStatus.NotFound }));
        vm.Update(Items(Router));

        Assert.True(vm.ShowUpnp);
        Assert.False(vm.HasPortMappings);
        Assert.Equal(Loc.T("upnp.notFound"), vm.UpnpHeadline);
        Assert.False(vm.NeedsAttention);
    }

    [AvaloniaFact]
    public void Turning_the_upnp_check_off_hides_the_section()
    {
        var vm = Create();
        vm.ApplyScan(Scan(upnp: null));
        vm.Update(Items(Router));

        Assert.False(vm.ShowUpnp);
        Assert.False(vm.HasPortMappings);
    }

    [AvaloniaFact]
    public void A_new_mapping_is_announced_once_and_never_on_the_first_reading()
    {
        var vm = Create();
        Assert.Empty(vm.ApplyScan(Scan(Report(Map(22, "192.168.1.40")), Homelab)).NewMappings); // linha de base

        var changes = vm.ApplyScan(Scan(Report(Map(22, "192.168.1.40"), Map(3074, "192.168.1.95", protocol: "UDP")), Homelab, Ps5));
        Assert.Equal(3074, Assert.Single(changes.NewMappings).ExternalPort);

        Assert.Empty(vm.ApplyScan(Scan(Report(Map(22, "192.168.1.40"), Map(3074, "192.168.1.95", protocol: "UDP")), Homelab, Ps5)).NewMappings);
    }

    // ---------------------------------------------------------------- O MAC do router

    private static ScanResult WithRouterMac(string mac, params DeviceInfo[] others) => new()
    {
        Network = new LocalNetworkInfo { IpAddress = "192.168.1.23", Gateway = "192.168.1.1" },
        Devices = [Device("192.168.1.1", mac, "router"), .. others]
    };

    [AvaloniaFact]
    public void A_changed_router_mac_raises_an_alert_announced_once_until_the_user_trusts_it()
    {
        var vm = Create();
        Assert.Null(vm.ApplyScan(WithRouterMac(RouterMac)).NewGatewayAlert);   // linha de base

        var first = vm.ApplyScan(WithRouterMac(OtherMac));
        vm.Update(Items(Router));
        Assert.NotNull(first.NewGatewayAlert);
        Assert.True(vm.HasGatewayAlert);
        Assert.Equal(Loc.T("gateway.weak.title"), vm.GatewayAlertTitle);
        Assert.Contains(OtherMac, vm.GatewayAlertText);
        Assert.Contains(RouterMac, vm.GatewayAlertText);
        Assert.True(vm.NeedsAttention);

        // Nos scans seguintes o cartão continua, mas o aviso (notificação) não se repete.
        var again = vm.ApplyScan(WithRouterMac(OtherMac));
        vm.Update(Items(Router));
        Assert.Null(again.NewGatewayAlert);
        Assert.True(vm.HasGatewayAlert);

        var trusted = 0;
        vm.GatewayTrusted += () => trusted++;
        vm.TrustGatewayCommand.Execute(null);

        Assert.Equal(1, trusted);
        Assert.False(vm.HasGatewayAlert);
        Assert.False(vm.NeedsAttention);
        Assert.Null(vm.ApplyScan(WithRouterMac(OtherMac)).NewGatewayAlert);    // aceite: já não é alerta
    }

    [AvaloniaFact]
    public void An_impostor_with_the_routers_mac_is_named_in_a_strong_alert()
    {
        var vm = Create();
        vm.ApplyScan(WithRouterMac(RouterMac));

        var intruder = Device("192.168.1.66", OtherMac, "portatil-estranho");
        var changes = vm.ApplyScan(WithRouterMac(OtherMac, intruder));
        vm.Update(Items(Router, intruder));

        Assert.True(changes.NewGatewayAlert!.IsStrong);
        Assert.Equal(Loc.T("gateway.strong.title"), vm.GatewayAlertTitle);
        Assert.Contains("portatil-estranho", vm.GatewayAlertText);
        Assert.Contains("192.168.1.66", vm.GatewayAlertText);
    }

    [AvaloniaFact]
    public void Trusting_with_no_alert_does_nothing()
    {
        var vm = Create();
        var raised = false;
        vm.GatewayTrusted += () => raised = true;
        vm.TrustGatewayCommand.Execute(null);
        Assert.False(raised);
    }

    // ---------------------------------------------------------------- O que a internet vê

    [AvaloniaFact]
    public async Task The_internet_check_never_runs_by_itself()
    {
        var lookup = new Lookup(Ok(22));
        var vm = Create(lookup);
        vm.ApplyScan(Scan(Report(Map(22, "192.168.1.40")), Homelab));
        vm.Update(Items(Router, Homelab));
        await Task.Yield();

        Assert.Empty(lookup.Asked);
        Assert.False(vm.HasInternetResult);
    }

    [AvaloniaFact]
    public async Task The_check_uses_the_routers_address_and_flags_ports_opened_by_upnp()
    {
        var lookup = new Lookup(Ok(22, 7547));
        var vm = Create(lookup);
        vm.ApplyScan(Scan(Report(Map(22, "192.168.1.40")), Homelab));
        vm.Update(Items(Router, Homelab));

        await vm.CheckInternetCommand.ExecuteAsync(null);

        Assert.Equal(["203.0.113.7"], lookup.Asked);       // o endereço vem do router: ninguém foi perguntado
        Assert.True(vm.HasInternetResult);
        Assert.Contains("203.0.113.7", vm.InternetHeadline);
        Assert.Equal([22, 7547], vm.InternetPorts.Select(p => p.Port));
        Assert.True(vm.InternetPorts[0].ViaUpnp);          // o router abriu-a por UPnP
        Assert.True(vm.InternetPorts[0].IsSensitive);      // SSH
        Assert.False(vm.InternetPorts[1].ViaUpnp);         // 7547 (TR-069): gestão do operador, não UPnP
        Assert.Equal("CVE-2018-15473", Assert.Single(vm.InternetVulns).Cve);
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2018-15473", vm.InternetVulns[0].Url);
        Assert.Equal(Loc.T("internet.recheck"), vm.InternetButtonText);
    }

    [AvaloniaFact]
    public async Task Without_upnp_the_lookup_is_asked_to_find_the_address_itself()
    {
        var lookup = new Lookup(new InternetExposure { Status = InternetCheckStatus.NothingSeen, Ip = "203.0.113.7" });
        var vm = Create(lookup);
        vm.ApplyScan(Scan(upnp: null));
        vm.Update(Items(Router));

        await vm.CheckInternetCommand.ExecuteAsync(null);

        Assert.Equal([(string?)null], lookup.Asked);
        Assert.False(vm.HasInternetPorts);
        Assert.Equal(string.Format(Loc.Instance.Culture, Loc.T("internet.nothing"), "203.0.113.7"), vm.InternetHeadline);
    }

    [AvaloniaFact]
    public async Task The_button_is_off_while_checking_and_back_afterwards()
    {
        var gate = new TaskCompletionSource();
        var vm = Create(new Lookup(Ok(22)) { Gate = gate });

        var running = vm.CheckInternetCommand.ExecuteAsync(null);
        Assert.True(vm.IsCheckingInternet);
        Assert.False(vm.CheckInternetCommand.CanExecute(null));
        Assert.Equal(Loc.T("internet.checking"), vm.InternetButtonText);

        gate.SetResult();
        await running;

        Assert.False(vm.IsCheckingInternet);
        Assert.True(vm.CheckInternetCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task A_failed_check_says_so_and_can_be_retried()
    {
        var vm = Create(new Lookup(new InternetExposure { Status = InternetCheckStatus.Failed }));
        await vm.CheckInternetCommand.ExecuteAsync(null);

        Assert.Equal(Loc.T("internet.failed"), vm.InternetHeadline);
        Assert.True(vm.CheckInternetCommand.CanExecute(null));
    }

    // ---------------------------------------------------------------- Idioma e opções

    [AvaloniaFact]
    public async Task Texts_follow_the_language()
    {
        var previous = Loc.Instance.Language;
        try
        {
            Loc.Instance.Language = "en";
            var vm = Create(new Lookup(Ok(22)));
            vm.ApplyScan(Scan(Report(Map(22, "192.168.1.40")), Homelab));
            vm.Update(Items(Router, Homelab));
            await vm.CheckInternetCommand.ExecuteAsync(null);
            var (upnpEn, internetEn, riskEn) = (vm.UpnpHeadline, vm.InternetHeadline, vm.PortMappings[0].RiskText);

            Loc.Instance.Language = "pt";
            vm.Update(Items(Router, Homelab));

            Assert.NotEqual(upnpEn, vm.UpnpHeadline);
            Assert.NotEqual(internetEn, vm.InternetHeadline);
            Assert.NotEqual(riskEn, vm.PortMappings[0].RiskText);
            Assert.Contains("internet", vm.UpnpHeadline);
        }
        finally
        {
            Loc.Instance.Language = previous;
        }
    }

    [AvaloniaFact]
    public void The_upnp_option_is_on_by_default_and_remembered()
    {
        var s = FilterTests.CreateWithDevices().Settings;
        var original = s.UpnpCheck;
        try
        {
            Assert.True(new AppSettings().UpnpCheck);
            s.UpnpCheck = !original;
            Assert.Equal(!original, AppSettings.Load().UpnpCheck);
        }
        finally
        {
            s.UpnpCheck = original;
        }
        Assert.Equal(original, AppSettings.Load().UpnpCheck);
    }
}
