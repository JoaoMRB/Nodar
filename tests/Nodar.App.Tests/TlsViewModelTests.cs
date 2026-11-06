using Avalonia.Headless.XUnit;
using Nodar.App.ViewModels;
using Nodar.Core.Localization;
using Nodar.Core.Models;
using Nodar.Core.Services;

namespace Nodar.App.Tests;

/// <summary>A secção "Certificados e TLS" da página de Segurança e o resumo TLS de cada serviço.</summary>
public class TlsViewModelTests
{
    private static TlsInfo Cert(DateTime? notAfter = null, string fingerprint = "AA", bool selfSigned = true, string issuer = "x", params string[] legacy)
    {
        var tls = new TlsInfo
        {
            Protocol = "TLS 1.2", Subject = "x", Issuer = issuer, SelfSigned = selfSigned,
            NotBefore = DateTime.Now.AddYears(-1), NotAfter = notAfter ?? DateTime.Now.AddYears(5), Fingerprint = fingerprint,
            KeyAlgorithm = "RSA", KeySize = 2048, SignatureAlgorithm = "sha256RSA"
        };
        tls.LegacyProtocols.AddRange(legacy);
        return tls;
    }

    private static DeviceItemViewModel Item(string ip, string host, (int Port, TlsInfo? Tls)[] services, bool online = true)
    {
        var device = new DeviceInfo
        {
            IpAddress = ip, MacAddress = "AA:BB:CC:00:00:" + int.Parse(ip.Split('.')[3]).ToString("X2"), Hostname = host,
            Services = [.. services.Select(s => new ServiceInfo { Port = s.Port, Service = "HTTPS", Tls = s.Tls })]
        };
        return new DeviceItemViewModel(device, null, device.MacAddress, isGateway: false, isOnline: online, isWatched: false);
    }

    private static SecurityViewModel Show(params DeviceItemViewModel[] devices)
    {
        TlsAnalyzer.MarkShared(devices.Select(d => d.Device));
        var vm = new SecurityViewModel();
        vm.Update(new ScanResult { Devices = [.. devices.Select(d => d.Device)] }, devices, 0);
        return vm;
    }

    [AvaloniaFact]
    public void Findings_are_listed_worst_first_with_their_device_and_port()
    {
        var vm = Show(
            Item("192.168.1.12", "impressora", [(443, Cert(legacy: ["TLS 1.0", "TLS 1.1"]))]),
            Item("192.168.1.52", "nas", [(8443, Cert(notAfter: DateTime.Now.AddDays(-10), fingerprint: "BB"))]));

        Assert.True(vm.ShowTls);
        Assert.True(vm.HasTlsFindings);
        Assert.Equal(2, vm.TlsFindings.Count);
        Assert.Equal(Loc.Plural("tls.count", 2), vm.TlsHeadline);

        var legacy = vm.TlsFindings.Single(f => f.Title == Loc.T("tls.legacy"));
        Assert.Equal("impressora · 192.168.1.12:443", legacy.Where);
        Assert.Contains("TLS 1.0, TLS 1.1", legacy.Detail);

        var expired = vm.TlsFindings.Single(f => f.Title == Loc.T("tls.expired"));
        Assert.Equal("nas · 192.168.1.52:8443", expired.Where);
        Assert.True(vm.TlsFindings[0].SeverityRank >= vm.TlsFindings[1].SeverityRank);
    }

    [AvaloniaFact]
    public void A_shared_factory_certificate_names_the_other_devices()
    {
        var vm = Show(
            Item("192.168.1.1", "router", [(443, Cert(fingerprint: "FACTORY"))]),
            Item("192.168.1.52", "nas", [(443, Cert(fingerprint: "FACTORY"))]));

        var forRouter = vm.TlsFindings.Single(f => f.Where.StartsWith("router"));
        Assert.Equal(Loc.T("tls.shared"), forRouter.Title);
        Assert.Contains("nas (192.168.1.52)", forRouter.Detail);   // nome e endereço do outro aparelho
        Assert.Equal("High", forRouter.Severity);
    }

    [AvaloniaFact]
    public void Healthy_tls_says_so_and_counts_what_was_checked()
    {
        var vm = Show(Item("192.168.1.1", "router", [(443, Cert()), (993, Cert(fingerprint: "BB"))]));

        Assert.True(vm.ShowTls);
        Assert.False(vm.HasTlsFindings);
        Assert.Equal(Loc.T("tls.ok"), vm.TlsHeadline);
        Assert.Equal(Loc.Plural("tls.checked", 2), vm.TlsDetail);
    }

    [AvaloniaFact]
    public void Without_inspected_tls_the_section_is_hidden()
    {
        // Sem serviços TLS (ou com a deteção de serviços desligada) não há nada a mostrar.
        Assert.False(Show(Item("192.168.1.1", "router", [])).ShowTls);
        Assert.False(Show(Item("192.168.1.1", "router", [(443, null)])).ShowTls);
    }

    [AvaloniaFact]
    public void Offline_devices_are_not_reported()
    {
        var vm = Show(Item("192.168.1.12", "impressora", [(443, Cert(legacy: ["TLS 1.0"]))], online: false));
        Assert.False(vm.ShowTls);
        Assert.Empty(vm.TlsFindings);
    }

    [AvaloniaFact]
    public void Texts_follow_the_language()
    {
        var previous = Loc.Instance.Language;
        try
        {
            Loc.Instance.Language = "en";
            var devices = new[] { Item("192.168.1.12", "impressora", [(443, Cert(legacy: ["TLS 1.0"]))]) };
            var vm = Show(devices);
            var (headlineEn, titleEn) = (vm.TlsHeadline, vm.TlsFindings[0].Title);

            Loc.Instance.Language = "pt";
            vm.Update(new ScanResult { Devices = [devices[0].Device] }, devices, 0);

            Assert.NotEqual(headlineEn, vm.TlsHeadline);
            Assert.NotEqual(titleEn, vm.TlsFindings[0].Title);
            Assert.Equal("Aceita protocolos TLS antigos", vm.TlsFindings[0].Title);
        }
        finally
        {
            Loc.Instance.Language = previous;
        }
    }

    [AvaloniaFact]
    public void A_service_row_summarises_its_certificate()
    {
        var selfSigned = new ServiceItemViewModel(new ServiceInfo { Port = 443, Tls = Cert(legacy: ["TLS 1.0"]) });
        Assert.True(selfSigned.HasTls);
        Assert.Contains("TLS 1.2", selfSigned.TlsText);
        Assert.Contains(Loc.T("tls.selfSigned"), selfSigned.TlsText);
        Assert.Contains("TLS 1.0", selfSigned.TlsText);

        var signed = new ServiceItemViewModel(new ServiceInfo { Port = 443, Tls = Cert(selfSigned: false, issuer: "Let's Encrypt") });
        Assert.Contains("Let's Encrypt", signed.TlsText);
        Assert.DoesNotContain(Loc.T("tls.selfSigned"), signed.TlsText);

        var plain = new ServiceItemViewModel(new ServiceInfo { Port = 80 });
        Assert.False(plain.HasTls);
        Assert.Equal("", plain.TlsText);
    }
}
