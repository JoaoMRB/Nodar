using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using Nodar.Core.Services;

namespace Nodar.Tests;

/// <summary>Leitura UPnP do router, vigia do MAC do router e consulta ao Shodan.</summary>
public sealed class ExposureTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-exposure-" + Guid.NewGuid().ToString("N"));
    private DateTime _now = new(2026, 11, 6, 10, 0, 0);

    public ExposureTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* limpeza de uma pasta temporária */ }
    }

    // ================================================================ Um router de mentira

    private const string IpV1 = "urn:schemas-upnp-org:service:WANIPConnection:1";
    private const string PppV1 = "urn:schemas-upnp-org:service:WANPPPConnection:1";
    private const string Location = "http://192.168.1.1:5000/desc.xml";

    private sealed class FakeHandler(Func<HttpRequestMessage, string, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content == null ? "" : await request.Content.ReadAsStringAsync(ct);
            lock (Requests) Requests.Add($"{request.Method} {request.RequestUri}");
            return respond(request, body);
        }
    }

    private static HttpResponseMessage Xml(string xml, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(xml, Encoding.UTF8, "text/xml") };

    private static string Envelope(string inner) =>
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>" + inner + "</s:Body></s:Envelope>";

    private static HttpResponseMessage Fault(int code) => Xml(Envelope(
        $"<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode><errorDescription>x</errorDescription></UPnPError></detail></s:Fault>"),
        HttpStatusCode.InternalServerError);

    private static string Entry(int external, int internalPort, string client, string protocol = "TCP",
        string description = "", string enabled = "1", string remote = "") =>
        $"<u:GetGenericPortMappingEntryResponse xmlns:u=\"{IpV1}\"><NewRemoteHost>{remote}</NewRemoteHost>" +
        $"<NewExternalPort>{external}</NewExternalPort><NewProtocol>{protocol}</NewProtocol><NewInternalPort>{internalPort}</NewInternalPort>" +
        $"<NewInternalClient>{client}</NewInternalClient><NewEnabled>{enabled}</NewEnabled>" +
        $"<NewPortMappingDescription>{description}</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse>";

    private static string Descriptor(string services, string urlBase = "") => $"""
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">{urlBase}
          <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
              <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                <serviceList>{services}</serviceList>
              </device></deviceList>
            </device></deviceList>
          </device>
        </root>
        """;

    private static string Service(string type, string control) =>
        $"<service><serviceType>{type}</serviceType><serviceId>urn:upnp-org:serviceId:x</serviceId><controlURL>{control}</controlURL></service>";

    /// <summary>Um router com UPnP: <paramref name="entries"/> são as respostas por índice; depois responde 713.</summary>
    private static FakeHandler Router(IReadOnlyList<string> entries, string externalIp = "203.0.113.7",
        string control = "/ctl/IPConn", string? descriptor = null) =>
        new((request, body) =>
        {
            if (request.Method == HttpMethod.Get)
                return Xml(descriptor ?? Descriptor(Service(IpV1, control)));

            var action = request.Headers.GetValues("SOAPACTION").Single();
            if (action.EndsWith("#GetExternalIPAddress\""))
                return Xml(Envelope($"<u:GetExternalIPAddressResponse xmlns:u=\"{IpV1}\"><NewExternalIPAddress>{externalIp}</NewExternalIPAddress></u:GetExternalIPAddressResponse>"));

            var index = int.Parse(Regex.Match(body, @"<NewPortMappingIndex>(\d+)<").Groups[1].Value);
            return index < entries.Count ? Xml(Envelope(entries[index])) : Fault(713);
        });

    // ================================================================ UPnP: ler o router

    [Fact]
    public async Task Reads_the_mappings_and_the_external_address()
    {
        var router = Router([
            Entry(554, 554, "192.168.1.40", "TCP", "Camara"),
            Entry(3074, 3074, "192.168.1.95", "UDP", "PlayStation", remote: "198.51.100.9")]);

        var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, router);

        Assert.Equal(UpnpStatus.Ok, report.Status);
        Assert.Equal("203.0.113.7", report.ExternalIp);
        Assert.Equal(2, report.Mappings.Count);
        var camera = report.Mappings[0];
        Assert.Equal(("TCP", 554, "192.168.1.40", 554, "Camara"), (camera.Protocol, camera.ExternalPort, camera.InternalClient, camera.InternalPort, camera.Description));
        Assert.True(camera.Enabled);
        Assert.True(camera.OpenToWholeInternet);
        Assert.False(report.Mappings[1].OpenToWholeInternet); // restrito a um só endereço da internet
        Assert.All(router.Requests, r => Assert.Contains("http://192.168.1.1:5000/", r)); // só se fala com o router
    }

    [Fact]
    public async Task A_router_with_no_mappings_is_ok_and_empty()
    {
        var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, Router([]));
        Assert.Equal(UpnpStatus.Ok, report.Status);
        Assert.Empty(report.Mappings);
        Assert.Equal("203.0.113.7", report.ExternalIp);
    }

    [Theory]
    [InlineData(501)]
    [InlineData(606)]
    [InlineData(401)]
    public async Task A_router_that_refuses_to_list_is_reported_as_such(int errorCode)
    {
        var handler = new FakeHandler((request, _) =>
        {
            if (request.Method == HttpMethod.Get)
                return Xml(Descriptor(Service(IpV1, "/ctl")));
            return request.Headers.GetValues("SOAPACTION").Single().Contains("GetExternalIPAddress")
                ? Xml(Envelope($"<u:GetExternalIPAddressResponse xmlns:u=\"{IpV1}\"><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse>"))
                : Fault(errorCode);
        });

        var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, handler);

        Assert.Equal(UpnpStatus.ListingRefused, report.Status);
        Assert.Equal("203.0.113.7", report.ExternalIp); // o endereço continua útil
        Assert.Empty(report.Mappings);
    }

    [Fact]
    public async Task Without_a_location_or_with_someone_elses_there_is_no_request_at_all()
    {
        var router = Router([Entry(1, 1, "192.168.1.5")]);

        var none = await UpnpGatewayClient.ReadAsync("192.168.1.1", null, CancellationToken.None, router);
        var elsewhere = await UpnpGatewayClient.ReadAsync("192.168.1.1", "http://203.0.113.50/desc.xml", CancellationToken.None, router);
        var https = await UpnpGatewayClient.ReadAsync("192.168.1.1", "https://192.168.1.1/desc.xml", CancellationToken.None, router);

        Assert.All(new[] { none, elsewhere, https }, r => Assert.Equal(UpnpStatus.NotFound, r.Status));
        Assert.Empty(router.Requests);
    }

    [Fact]
    public async Task A_descriptor_pointing_the_control_url_at_another_machine_is_ignored()
    {
        var evil = Descriptor(Service(IpV1, "http://192.168.1.99:80/steal"));
        var viaBase = Descriptor(Service(IpV1, "/ctl"), "<URLBase>http://192.168.1.99:80/</URLBase>");

        foreach (var descriptor in new[] { evil, viaBase })
        {
            var router = Router([Entry(1, 1, "192.168.1.5")], descriptor: descriptor);
            var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, router);

            Assert.Equal(UpnpStatus.NotFound, report.Status);
            Assert.Equal(["GET http://192.168.1.1:5000/desc.xml"], router.Requests); // nunca falou com o .99
        }
    }

    [Fact]
    public async Task A_relative_control_url_is_resolved_against_the_descriptor()
    {
        var router = Router([Entry(1, 1, "192.168.1.5")], control: "ctl/IPConn");
        var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, router);

        Assert.Equal(UpnpStatus.Ok, report.Status);
        Assert.Contains("POST http://192.168.1.1:5000/ctl/IPConn", router.Requests);
    }

    [Fact]
    public async Task A_router_that_never_stops_listing_is_cut_at_the_limit()
    {
        var handler = new FakeHandler((request, body) =>
        {
            if (request.Method == HttpMethod.Get)
                return Xml(Descriptor(Service(IpV1, "/ctl")));
            if (request.Headers.GetValues("SOAPACTION").Single().Contains("GetExternalIPAddress"))
                return Fault(501);
            var index = int.Parse(Regex.Match(body, @"<NewPortMappingIndex>(\d+)<").Groups[1].Value);
            return Xml(Envelope(Entry(1000 + index, 80, "192.168.1.5")));
        });

        var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, handler);

        Assert.Equal(UpnpStatus.Ok, report.Status);
        Assert.True(report.Truncated);
        Assert.Equal(UpnpGatewayClient.MaxMappings, report.Mappings.Count);
    }

    [Fact]
    public async Task Garbage_and_external_entities_from_the_router_are_a_failure_not_a_crash()
    {
        var xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE root [ <!ENTITY x SYSTEM "file:///C:/Windows/win.ini"> ]>
            <root>&x;</root>
            """;
        foreach (var body in new[] { xxe, "isto não é xml" })
        {
            var handler = new FakeHandler((_, _) => Xml(body));
            var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, handler);
            Assert.Equal(UpnpStatus.Failed, report.Status);
        }
    }

    [Fact]
    public async Task Cancelling_stops_the_reading()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            UpnpGatewayClient.ReadAsync("192.168.1.1", Location, cts.Token, Router([])));
    }

    [Fact]
    public async Task When_the_ip_service_is_unused_the_ppp_one_is_read()
    {
        // Routers DSL: o serviço IP existe mas está sem ligação (0.0.0.0, sem redirecionamentos); o PPP é o que vale.
        var descriptor = Descriptor(Service(IpV1, "/ip") + Service(PppV1, "/ppp"));
        var handler = new FakeHandler((request, body) =>
        {
            if (request.Method == HttpMethod.Get)
                return Xml(descriptor);
            var onPpp = request.RequestUri!.AbsolutePath == "/ppp";
            var action = request.Headers.GetValues("SOAPACTION").Single();
            if (action.Contains("GetExternalIPAddress"))
                return Xml(Envelope($"<u:R xmlns:u=\"x\"><NewExternalIPAddress>{(onPpp ? "203.0.113.7" : "0.0.0.0")}</NewExternalIPAddress></u:R>"));
            return onPpp && body.Contains(">0<") ? Xml(Envelope(Entry(22, 22, "192.168.1.40"))) : Fault(713);
        });

        var report = await UpnpGatewayClient.ReadAsync("192.168.1.1", Location, CancellationToken.None, handler);

        Assert.Equal("203.0.113.7", report.ExternalIp);
        Assert.Equal(22, Assert.Single(report.Mappings).ExternalPort);
    }

    [Fact]
    public void Mapping_text_from_the_router_is_cleaned_and_bad_entries_are_dropped()
    {
        IReadOnlyDictionary<string, string> Fields(string port = "80", string client = "192.168.1.5", string protocol = "tcp", string description = "ok") =>
            new Dictionary<string, string>
            {
                ["NewExternalPort"] = port, ["NewInternalPort"] = "80", ["NewInternalClient"] = client,
                ["NewProtocol"] = protocol, ["NewPortMappingDescription"] = description, ["NewEnabled"] = "True"
            };

        var long80 = new string('x', 500);
        var mapping = UpnpGatewayClient.ParseMapping(Fields(description: "Jogo\u0007\nXbox" + long80));
        Assert.NotNull(mapping);
        Assert.Equal("TCP", mapping.Protocol);
        Assert.DoesNotContain(mapping.Description, c => char.IsControl(c));
        Assert.True(mapping.Description.Length <= 80);
        Assert.True(mapping.Enabled);

        Assert.Null(UpnpGatewayClient.ParseMapping(Fields(port: "0")));
        Assert.Null(UpnpGatewayClient.ParseMapping(Fields(port: "70000")));
        Assert.Null(UpnpGatewayClient.ParseMapping(Fields(client: "não-é-ip")));
        Assert.Null(UpnpGatewayClient.ParseMapping(Fields(protocol: "ICMP")));
    }

    [Fact]
    public void Sensitive_services_are_recognised_by_their_destination_port()
    {
        Assert.Equal("RDP", ExposureAdvice.SensitiveService(3389));
        Assert.Equal("RTSP", ExposureAdvice.SensitiveService(554));
        Assert.Null(ExposureAdvice.SensitiveService(80));
        Assert.Equal("HTTP", ExposureAdvice.PortName(80));
        Assert.Null(ExposureAdvice.PortName(31337));
    }

    [Fact]
    public void Temporary_non_sensitive_ports_do_not_interrupt_with_a_system_notification()
    {
        PortMapping Make(int port, int lease) => new()
            { Protocol = "UDP", ExternalPort = port, InternalClient = "192.168.1.16", InternalPort = port, LeaseSeconds = lease };

        Assert.False(ExposureAdvice.WorthSystemNotice(Make(22810, lease: 2556))); // Parsec: renova-se sozinho
        Assert.True(ExposureAdvice.WorthSystemNotice(Make(22810, lease: 0)));     // permanente
        Assert.True(ExposureAdvice.WorthSystemNotice(Make(3389, lease: 3600)));   // RDP: sensível, mesmo temporário
    }

    // ================================================================ Portas abertas: o que é novo

    private PortMappingTracker Tracker()
    {
        var t = new PortMappingTracker(_dir, () => _now);
        t.Load();
        return t;
    }

    private static PortMapping Map(int external, string client = "192.168.1.40", bool enabled = true) =>
        new() { Protocol = "TCP", ExternalPort = external, InternalClient = client, InternalPort = external, Enabled = enabled };

    private static UpnpReport Ok(params PortMapping[] mappings) => new() { Status = UpnpStatus.Ok, Mappings = [.. mappings] };

    [Fact]
    public void The_first_reading_is_the_baseline_and_announces_nothing()
    {
        Assert.Empty(Tracker().Apply(Ok(Map(554), Map(22))));
    }

    [Fact]
    public void A_mapping_that_appears_later_is_new_once_and_remembers_since_when()
    {
        var t = Tracker();
        t.Apply(Ok(Map(554)));

        _now = _now.AddDays(1);
        var added = t.Apply(Ok(Map(554), Map(22)));
        Assert.Equal(22, Assert.Single(added).ExternalPort);
        Assert.Equal(_now, t.FirstSeen(Map(22)));
        Assert.Equal(_now.AddDays(-1), t.FirstSeen(Map(554)));

        Assert.Empty(t.Apply(Ok(Map(554), Map(22)))); // já não é novo
    }

    [Fact]
    public void What_was_seen_survives_a_restart()
    {
        Tracker().Apply(Ok(Map(554)));
        var again = Tracker();
        Assert.Empty(again.Apply(Ok(Map(554))));
        Assert.Single(again.Apply(Ok(Map(554), Map(22))));
    }

    [Fact]
    public void A_disabled_mapping_is_not_announced()
    {
        var t = Tracker();
        t.Apply(Ok());
        Assert.Empty(t.Apply(Ok(Map(22, enabled: false))));
    }

    [Fact]
    public void A_momentary_empty_reading_does_not_make_old_mappings_look_new()
    {
        var t = Tracker();
        t.Apply(Ok(Map(554)));

        t.Apply(Ok());                                     // o router falhou uma leitura
        Assert.Empty(t.Apply(Ok(Map(554))));               // voltou: não é novo
    }

    [Fact]
    public void A_mapping_that_stays_gone_is_forgotten_and_is_new_if_it_returns()
    {
        var t = Tracker();
        t.Apply(Ok(Map(554)));
        for (var i = 0; i < PortMappingTracker.MissedBeforeForgotten; i++)
            t.Apply(Ok());

        Assert.Null(t.FirstSeen(Map(554)));
        Assert.Single(t.Apply(Ok(Map(554))));
    }

    [Fact]
    public void Failed_or_truncated_readings_forget_nothing()
    {
        var t = Tracker();
        t.Apply(Ok(Map(554)));

        for (var i = 0; i < 5; i++)
        {
            t.Apply(new UpnpReport { Status = UpnpStatus.Failed });
            t.Apply(new UpnpReport { Status = UpnpStatus.Ok, Truncated = true });
        }
        Assert.NotNull(t.FirstSeen(Map(554)));
    }

    // ================================================================ MAC do router

    private GatewayGuard Guard()
    {
        var g = new GatewayGuard(_dir);
        g.Load();
        return g;
    }

    private static DeviceInfo Dev(string ip, string mac) => new() { IpAddress = ip, MacAddress = mac };

    private static readonly DeviceInfo Router1 = Dev("192.168.1.1", "D0:CF:0E:00:00:01");
    private static readonly DeviceInfo Laptop = Dev("192.168.1.23", "3C:22:FB:10:4A:01");

    [Fact]
    public void The_first_router_seen_is_trusted_without_an_alert()
    {
        var g = Guard();
        Assert.Null(g.Evaluate("192.168.1.1", [Router1, Laptop]));
        Assert.Equal(["D0:CF:0E:00:00:01"], g.TrustedMacs("192.168.1.1"));
    }

    [Fact]
    public void The_same_router_never_raises_an_alert()
    {
        var g = Guard();
        g.Evaluate("192.168.1.1", [Router1]);
        Assert.Null(g.Evaluate("192.168.1.1", [Router1, Laptop]));
        Assert.Null(g.Evaluate("192.168.1.1", [Dev("192.168.1.1", "D0-CF-0E-00-00-01")])); // outra grafia do mesmo MAC
    }

    [Fact]
    public void A_new_mac_for_the_router_is_a_weak_alert()
    {
        var g = Guard();
        g.Evaluate("192.168.1.1", [Router1]);

        var alert = g.Evaluate("192.168.1.1", [Dev("192.168.1.1", "AA:BB:CC:00:00:09"), Laptop]);

        Assert.NotNull(alert);
        Assert.Equal(("D0:CF:0E:00:00:01", "AA:BB:CC:00:00:09"), (alert.KnownMac, alert.NewMac));
        Assert.False(alert.IsStrong);
        Assert.Null(alert.OtherDeviceIp);
    }

    [Fact]
    public void Another_device_with_the_routers_new_mac_is_a_strong_alert()
    {
        var g = Guard();
        g.Evaluate("192.168.1.1", [Router1]);

        // O atacante (192.168.1.66) responde pelo router com a sua própria placa.
        var alert = g.Evaluate("192.168.1.1",
            [Dev("192.168.1.1", "AA:BB:CC:00:00:09"), Dev("192.168.1.66", "AA:BB:CC:00:00:09"), Laptop]);

        Assert.NotNull(alert);
        Assert.True(alert.IsStrong);
        Assert.Equal("192.168.1.66", alert.OtherDeviceIp);
    }

    [Fact]
    public void The_alert_stays_until_the_user_trusts_the_new_mac()
    {
        var g = Guard();
        g.Evaluate("192.168.1.1", [Router1]);
        var changed = new[] { Dev("192.168.1.1", "AA:BB:CC:00:00:09") };

        Assert.NotNull(g.Evaluate("192.168.1.1", changed));
        Assert.NotNull(g.Evaluate("192.168.1.1", changed)); // não se cala sozinho

        g.Trust("192.168.1.1", "AA:BB:CC:00:00:09");
        Assert.Null(g.Evaluate("192.168.1.1", changed));
        Assert.Null(g.Evaluate("192.168.1.1", [Router1]));  // o antigo continua de confiança (voltar a casa)
    }

    [Fact]
    public void Trusted_macs_survive_a_restart()
    {
        var g = Guard();
        g.Evaluate("192.168.1.1", [Router1]);
        g.Trust("192.168.1.1", "AA:BB:CC:00:00:09");

        var again = Guard();
        Assert.Null(again.Evaluate("192.168.1.1", [Dev("192.168.1.1", "AA:BB:CC:00:00:09")]));
        Assert.Null(again.Evaluate("192.168.1.1", [Router1]));
    }

    [Fact]
    public void A_router_without_a_usable_mac_is_ignored_and_never_becomes_the_baseline()
    {
        var g = Guard();
        Assert.Null(g.Evaluate("192.168.1.1", [Dev("192.168.1.1", "—")]));
        Assert.Null(g.Evaluate("192.168.1.1", [Dev("192.168.1.1", "")]));
        Assert.Null(g.Evaluate("192.168.1.1", [Laptop])); // router fora da lista
        Assert.Empty(g.TrustedMacs("192.168.1.1"));

        g.Trust("192.168.1.1", "lixo");
        Assert.Empty(g.TrustedMacs("192.168.1.1"));
    }

    [Fact]
    public void Each_gateway_address_has_its_own_trusted_macs()
    {
        var g = Guard();
        g.Evaluate("192.168.1.1", [Router1]);
        // Outra rede com outro router em 10.0.0.1 não é uma mudança do primeiro.
        Assert.Null(g.Evaluate("10.0.0.1", [Dev("10.0.0.1", "AA:BB:CC:00:00:09")]));
        Assert.Null(g.Evaluate("192.168.1.1", [Router1]));
    }

    [Fact]
    public void A_corrupt_gateway_file_starts_empty_and_keeps_a_copy()
    {
        File.WriteAllText(Path.Combine(_dir, "gateway.json"), "{ não é json");
        var g = Guard();

        Assert.Null(g.Evaluate("192.168.1.1", [Router1]));
        Assert.Equal("{ não é json", File.ReadAllText(Path.Combine(_dir, "gateway.json.corrupt")));
    }

    // ================================================================ O que a internet vê (Shodan)

    private const string ShodanJson = """
        {"cpes":["cpe:/a:openbsd:openssh:7.4"],"hostnames":["casa.exemplo.pt"],"ip":"203.0.113.7",
         "ports":[443,22,7547,22],"tags":["self-signed"],"vulns":["CVE-2018-15473","CVE-2016-0777","isto;rm -rf","CVE-2018-15473"]}
        """;

    [Fact]
    public void Parses_what_shodan_saw()
    {
        var seen = InternetExposureService.Parse(ShodanJson, "203.0.113.7", _now);

        Assert.Equal(InternetCheckStatus.Ok, seen.Status);
        Assert.Equal([22, 443, 7547], seen.Ports);                                // ordenadas, sem repetidas
        Assert.Equal(["CVE-2016-0777", "CVE-2018-15473"], seen.Vulns);            // só o formato exato de um CVE
        Assert.Equal(["casa.exemplo.pt"], seen.Hostnames);
        Assert.Equal(["self-signed"], seen.Tags);
    }

    [Fact]
    public void An_empty_answer_means_nothing_was_seen()
    {
        var seen = InternetExposureService.Parse("""{"ip":"203.0.113.7","ports":[],"vulns":[],"hostnames":[],"tags":[],"cpes":[]}""", "203.0.113.7", _now);
        Assert.Equal(InternetCheckStatus.NothingSeen, seen.Status);
    }

    [Fact]
    public async Task Asks_shodan_about_the_address_the_router_gave()
    {
        var handler = new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(ShodanJson) });

        var seen = await InternetExposureService.CheckAsync("203.0.113.7", CancellationToken.None, handler, () => _now);

        Assert.Equal(InternetCheckStatus.Ok, seen.Status);
        Assert.Equal("203.0.113.7", seen.Ip);
        Assert.Equal(["GET https://internetdb.shodan.io/203.0.113.7"], handler.Requests); // não perguntou o IP a ninguém
    }

    [Fact]
    public async Task A_404_means_shodan_saw_nothing()
    {
        var handler = new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.NotFound));
        var seen = await InternetExposureService.CheckAsync("203.0.113.7", CancellationToken.None, handler);
        Assert.Equal(InternetCheckStatus.NothingSeen, seen.Status);
    }

    [Theory]
    [InlineData("192.168.0.10")]   // duplo NAT
    [InlineData("100.72.5.9")]     // CGNAT do operador
    [InlineData("10.1.2.3")]
    [InlineData("169.254.1.1")]
    public async Task A_non_public_address_is_never_sent_anywhere(string ip)
    {
        var handler = new FakeHandler((_, _) => throw new InvalidOperationException("não devia haver pedidos"));

        var seen = await InternetExposureService.CheckAsync(ip, CancellationToken.None, handler);

        Assert.Equal(InternetCheckStatus.NotPublic, seen.Status);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Without_an_address_from_the_router_the_public_one_is_looked_up_first()
    {
        var handler = new FakeHandler((request, _) =>
            request.RequestUri!.Host == "api.ipify.org"
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("203.0.113.7\n") }
                : new HttpResponseMessage(HttpStatusCode.NotFound));

        var seen = await InternetExposureService.CheckAsync(null, CancellationToken.None, handler);

        Assert.Equal(InternetCheckStatus.NothingSeen, seen.Status);
        Assert.Equal("203.0.113.7", seen.Ip);
        Assert.Equal(["GET https://api.ipify.org/", "GET https://internetdb.shodan.io/203.0.113.7"], handler.Requests);
    }

    [Fact]
    public async Task Failures_are_reported_not_thrown()
    {
        var serverError = new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.TooManyRequests));
        Assert.Equal(InternetCheckStatus.Failed, (await InternetExposureService.CheckAsync("203.0.113.7", CancellationToken.None, serverError)).Status);

        var offline = new FakeHandler((_, _) => throw new HttpRequestException("sem internet"));
        Assert.Equal(InternetCheckStatus.Failed, (await InternetExposureService.CheckAsync("203.0.113.7", CancellationToken.None, offline)).Status);

        var garbage = new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>") });
        Assert.Equal(InternetCheckStatus.Failed, (await InternetExposureService.CheckAsync("203.0.113.7", CancellationToken.None, garbage)).Status);
    }

    [Fact]
    public async Task Cancelling_the_check_is_not_swallowed()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var handler = new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            InternetExposureService.CheckAsync("203.0.113.7", cts.Token, handler));
    }

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("203.0.113.7", true)]
    [InlineData("172.15.0.1", true)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("100.128.0.1", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("2001:db8::1", false)]
    public void Only_routable_ipv4_addresses_count_as_public(string ip, bool expected) =>
        Assert.Equal(expected, InternetExposureService.IsPublicIPv4(IPAddress.Parse(ip)));
}
