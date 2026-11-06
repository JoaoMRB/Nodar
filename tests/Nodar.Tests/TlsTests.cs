using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nodar.Core.Models;
using Nodar.Core.Services;

namespace Nodar.Tests;

/// <summary>Inspeção do TLS (certificado e protocolos antigos) e a análise dos problemas.</summary>
public sealed class TlsTests : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _serverCts = new(TimeSpan.FromSeconds(30));
    private static readonly DateTime Now = new(2026, 11, 6, 12, 0, 0);

    public TlsTests() => _listener.Start();

    private int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public void Dispose()
    {
        _serverCts.Cancel();
        _listener.Stop();
        _serverCts.Dispose();
    }

    private static readonly TlsInspector.InspectOptions NoLegacy = new()
    {
        ConnectTimeout = TimeSpan.FromSeconds(2),
        HandshakeTimeout = TimeSpan.FromSeconds(5),
        ProbeTimeout = TimeSpan.FromMilliseconds(500),
        CheckLegacy = false
    };

    private static readonly TlsInspector.InspectOptions Quick = NoLegacy with { CheckLegacy = true };

    private static X509Certificate2 MakeCertificate(string name, DateTimeOffset notBefore, DateTimeOffset notAfter, int rsaBits = 2048)
    {
        using var rsa = RSA.Create(rsaBits);
        var request = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = request.CreateSelfSigned(notBefore, notAfter);
        // No Windows o SChannel precisa de uma chave importada (não efémera).
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
    }

    /// <summary>Um servidor TLS a sério que aceita uma ligação.</summary>
    private Task ServeTls(X509Certificate2 certificate) => Task.Run(async () =>
    {
        using var client = await _listener.AcceptTcpClientAsync(_serverCts.Token);
        await using var ssl = new SslStream(client.GetStream());
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, _serverCts.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(300), _serverCts.Token).ContinueWith(_ => { });
    });

    /// <summary>
    /// Um servidor antigo que só percebe ClientHello e responde como um TLS real: com um ServerHello na versão que
    /// oferecemos se a suporta, ou com um alerta se não. Aceita <paramref name="connections"/> ligações.
    /// </summary>
    private Task ServeLegacy(ushort minVersion, ushort maxVersion, int connections) => Task.Run(async () =>
    {
        for (var i = 0; i < connections; i++)
        {
            using var client = await _listener.AcceptTcpClientAsync(_serverCts.Token);
            var stream = client.GetStream();
            var hello = new byte[512];
            var read = await stream.ReadAsync(hello, _serverCts.Token);
            if (read < 11)
                continue;

            var offered = (ushort)((hello[9] << 8) | hello[10]);
            if (offered < minVersion)
            {
                await stream.WriteAsync(new byte[] { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46 }, _serverCts.Token); // alerta: protocol_version
                continue;
            }
            var chosen = Math.Min(offered, maxVersion);
            var serverHello = new byte[] { 0x16, 0x03, 0x01, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2C, (byte)(chosen >> 8), (byte)chosen };
            await stream.WriteAsync(serverHello, _serverCts.Token);
        }
    });

    // ================================================================ Certificado

    [Fact]
    public async Task Reads_the_certificate_and_the_negotiated_protocol()
    {
        using var certificate = MakeCertificate("router-casa", DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(300));
        var server = ServeTls(certificate);

        var tls = await TlsInspector.InspectAsync("127.0.0.1", Port, CancellationToken.None, NoLegacy);

        Assert.NotNull(tls);
        Assert.Equal("router-casa", tls.Subject);
        Assert.True(tls.SelfSigned);
        Assert.Equal("RSA", tls.KeyAlgorithm);
        Assert.Equal(2048, tls.KeySize);
        Assert.Contains("sha256", tls.SignatureAlgorithm, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(certificate.RawData)), tls.Fingerprint);
        Assert.StartsWith("TLS 1.", tls.Protocol);
        Assert.True(tls.NotAfter > DateTime.Now.AddDays(200));
        Assert.Empty(tls.LegacyProtocols);                     // sem testar protocolos antigos
        await server;
    }

    [Fact]
    public async Task An_expired_certificate_is_still_read()
    {
        using var certificate = MakeCertificate("velho", DateTimeOffset.UtcNow.AddYears(-3), DateTimeOffset.UtcNow.AddYears(-1));
        var server = ServeTls(certificate);

        var tls = await TlsInspector.InspectAsync("127.0.0.1", Port, CancellationToken.None, NoLegacy);

        Assert.NotNull(tls);
        Assert.True(tls.NotAfter < DateTime.Now);
        Assert.Contains(TlsAnalyzer.Analyze(tls, Port, DateTime.Now), f => f.Kind == TlsFindingKind.Expired);
        await server;
    }

    [Fact]
    public async Task A_port_that_does_not_speak_tls_gives_nothing()
    {
        var server = Task.Run(async () =>
        {
            using var client = await _listener.AcceptTcpClientAsync(_serverCts.Token);
            await client.GetStream().WriteAsync("SSH-2.0-OpenSSH_8.9\r\n"u8.ToArray(), _serverCts.Token);
            await Task.Delay(TimeSpan.FromSeconds(1), _serverCts.Token).ContinueWith(_ => { });
        });

        Assert.Null(await TlsInspector.InspectAsync("127.0.0.1", Port, CancellationToken.None, NoLegacy));
    }

    [Fact]
    public async Task A_closed_port_gives_nothing_and_cancelling_is_not_swallowed()
    {
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        var port = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();
        Assert.Null(await TlsInspector.InspectAsync("127.0.0.1", port, CancellationToken.None, NoLegacy));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => TlsInspector.InspectAsync("127.0.0.1", Port, cts.Token, NoLegacy));
    }

    // ================================================================ Protocolos antigos

    [Theory]
    [InlineData(0x0300, 0x0303, new[] { "SSL 3.0", "TLS 1.0", "TLS 1.1" })]   // aceita tudo
    [InlineData(0x0301, 0x0303, new[] { "TLS 1.0", "TLS 1.1" })]
    [InlineData(0x0302, 0x0303, new[] { "TLS 1.1" })]
    [InlineData(0x0303, 0x0304, new string[0])]                                  // um servidor moderno: só TLS 1.2 ou mais
    public async Task Finds_which_obsolete_protocols_the_server_still_accepts(int min, int max, string[] expected)
    {
        var server = ServeLegacy((ushort)min, (ushort)max, connections: 3);

        var accepted = await TlsInspector.LegacyProtocolsAsync("127.0.0.1", Port, CancellationToken.None, Quick);

        Assert.Equal(expected, accepted);
        await server;
    }

    [Fact]
    public async Task A_server_that_only_speaks_tls_10_is_not_reported_as_accepting_11()
    {
        // Oferecida a versão 1.1, responde com 1.0 (o máximo que tem): só o 1.0 conta.
        var server = ServeLegacy(0x0301, 0x0301, connections: 3);

        var accepted = await TlsInspector.LegacyProtocolsAsync("127.0.0.1", Port, CancellationToken.None, Quick);

        Assert.Equal(["TLS 1.0"], accepted);
        await server;
    }

    [Fact]
    public async Task A_silent_server_is_not_reported_as_accepting_anything_and_does_not_hang()
    {
        var server = Task.Run(async () =>
        {
            for (var i = 0; i < 3; i++)
            {
                using var client = await _listener.AcceptTcpClientAsync(_serverCts.Token);
                await Task.Delay(TimeSpan.FromSeconds(2), _serverCts.Token).ContinueWith(_ => { });
            }
        });

        var watch = System.Diagnostics.Stopwatch.StartNew();
        var accepted = await TlsInspector.LegacyProtocolsAsync("127.0.0.1", Port, CancellationToken.None, Quick);

        Assert.Empty(accepted);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(4), $"demorou {watch.Elapsed}");
    }

    [Theory]
    [InlineData(0x0300)]
    [InlineData(0x0301)]
    [InlineData(0x0302)]
    public void The_client_hello_offers_exactly_the_requested_version(int version)
    {
        var hello = TlsInspector.BuildClientHello((ushort)version);

        Assert.Equal(0x16, hello[0]);                                         // registo de handshake
        Assert.Equal(hello.Length - 5, (hello[3] << 8) | hello[4]);           // tamanho do registo
        Assert.Equal(0x01, hello[5]);                                         // ClientHello
        Assert.Equal(hello.Length - 9, (hello[6] << 16) | (hello[7] << 8) | hello[8]); // tamanho do handshake
        Assert.Equal(version, (hello[9] << 8) | hello[10]);                   // versão oferecida
    }

    [Fact]
    public void Only_a_server_hello_in_the_offered_version_counts_as_accepted()
    {
        byte[] Reply(byte type, byte hi, byte lo) => [0x16, 0x03, 0x01, 0x00, 0x30, type, 0x00, 0x00, 0x2C, hi, lo];

        Assert.True(TlsInspector.IsServerHello(Reply(0x02, 0x03, 0x01), 0x0301));
        Assert.False(TlsInspector.IsServerHello(Reply(0x02, 0x03, 0x03), 0x0301));  // respondeu com outra versão
        Assert.False(TlsInspector.IsServerHello(Reply(0x0B, 0x03, 0x01), 0x0301));  // não é um ServerHello
        Assert.False(TlsInspector.IsServerHello([0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46, 0, 0, 0, 0], 0x0301)); // alerta
        Assert.False(TlsInspector.IsServerHello([0x16, 0x03], 0x0301));             // curto demais
    }

    // ================================================================ Análise

    private static TlsInfo Info(Action<TlsInfoBuilder>? tweak = null)
    {
        var b = new TlsInfoBuilder();
        tweak?.Invoke(b);
        return b.Build();
    }

    private sealed class TlsInfoBuilder
    {
        public DateTime NotBefore = Now.AddYears(-1);
        public DateTime NotAfter = Now.AddYears(5);
        public bool SelfSigned = true;
        public string Key = "RSA";
        public int KeySize = 2048;
        public string Signature = "sha256RSA";
        public string Fingerprint = "AA";
        public string[] Legacy = [];

        public TlsInfo Build()
        {
            var info = new TlsInfo
            {
                Subject = "x", Issuer = "x", NotBefore = NotBefore, NotAfter = NotAfter, Fingerprint = Fingerprint,
                SelfSigned = SelfSigned, KeyAlgorithm = Key, KeySize = KeySize, SignatureAlgorithm = Signature
            };
            info.LegacyProtocols.AddRange(Legacy);
            return info;
        }
    }

    [Fact]
    public void A_normal_self_signed_certificate_has_no_findings()
    {
        // Autoassinado é o normal em routers e IoT: não se assinala.
        Assert.Empty(TlsAnalyzer.Analyze(Info(), 443, Now));
        Assert.Empty(TlsAnalyzer.Analyze(Info(b => { b.Key = "ECC"; b.KeySize = 256; b.Signature = "sha256ECDSA"; }), 443, Now));
    }

    [Fact]
    public void Validity_problems_are_found()
    {
        var expired = TlsAnalyzer.Analyze(Info(b => b.NotAfter = Now.AddDays(-1)), 443, Now);
        Assert.Equal(TlsFindingKind.Expired, Assert.Single(expired).Kind);
        Assert.Equal(Now.AddDays(-1), expired[0].When);

        var soon = TlsAnalyzer.Analyze(Info(b => b.NotAfter = Now.AddDays(29)), 443, Now);
        Assert.Equal(TlsFindingKind.ExpiresSoon, Assert.Single(soon).Kind);

        Assert.Empty(TlsAnalyzer.Analyze(Info(b => b.NotAfter = Now.AddDays(31)), 443, Now));

        var future = TlsAnalyzer.Analyze(Info(b => b.NotBefore = Now.AddDays(2)), 443, Now);
        Assert.Equal(TlsFindingKind.NotYetValid, Assert.Single(future).Kind);
    }

    [Fact]
    public void Obsolete_protocols_are_findings_and_ssl3_is_worse()
    {
        var tls10 = Assert.Single(TlsAnalyzer.Analyze(Info(b => b.Legacy = ["TLS 1.0", "TLS 1.1"]), 443, Now));
        Assert.Equal((TlsFindingKind.LegacyProtocol, "Medium", "TLS 1.0, TLS 1.1"), (tls10.Kind, tls10.Severity, tls10.Arg));

        var ssl3 = Assert.Single(TlsAnalyzer.Analyze(Info(b => b.Legacy = ["SSL 3.0", "TLS 1.0"]), 443, Now));
        Assert.Equal("High", ssl3.Severity);
    }

    [Theory]
    [InlineData("RSA", 1024, true)]
    [InlineData("RSA", 2048, false)]
    [InlineData("RSA", 4096, false)]
    [InlineData("ECC", 192, true)]
    [InlineData("ECC", 256, false)]
    [InlineData("RSA", 0, false)]      // tamanho desconhecido: não se acusa
    [InlineData("Ed25519", 128, false)]
    public void Short_keys_are_findings(string algorithm, int size, bool weak)
    {
        var findings = TlsAnalyzer.Analyze(Info(b => { b.Key = algorithm; b.KeySize = size; }), 443, Now);
        Assert.Equal(weak, findings.Any(f => f.Kind == TlsFindingKind.WeakKey));
    }

    [Theory]
    [InlineData("md5RSA", true)]
    [InlineData("sha1RSA", true)]
    [InlineData("sha1ECDSA", true)]
    [InlineData("sha256RSA", false)]
    [InlineData("sha384ECDSA", false)]
    public void Weak_signatures_are_findings(string signature, bool weak)
    {
        var findings = TlsAnalyzer.Analyze(Info(b => b.Signature = signature), 443, Now);
        Assert.Equal(weak, findings.Any(f => f.Kind == TlsFindingKind.WeakSignature));
    }

    // ---------------------------------------------------------------- Certificado partilhado

    private static DeviceInfo Device(string ip, params (int Port, TlsInfo Tls)[] services) => new()
    {
        IpAddress = ip,
        Services = [.. services.Select(s => new ServiceInfo { Port = s.Port, Service = "HTTPS", Tls = s.Tls })]
    };

    [Fact]
    public void The_same_self_signed_certificate_on_two_devices_is_marked_on_both()
    {
        var (a, b, c) = (Info(), Info(), Info(x => x.Fingerprint = "BB"));
        MarkAndCheck([Device("192.168.1.1", (443, a)), Device("192.168.1.40", (443, b)), Device("192.168.1.50", (443, c))]);

        Assert.Equal(["192.168.1.40"], a.SharedWith);
        Assert.Equal(["192.168.1.1"], b.SharedWith);
        Assert.Empty(c.SharedWith);

        var finding = Assert.Single(TlsAnalyzer.Analyze(a, 443, Now));
        Assert.Equal((TlsFindingKind.SharedCertificate, "High", "192.168.1.40"), (finding.Kind, finding.Severity, finding.Arg));
    }

    private static void MarkAndCheck(IReadOnlyList<DeviceInfo> devices) => TlsAnalyzer.MarkShared(devices);

    [Fact]
    public void One_device_with_the_certificate_on_two_ports_is_not_sharing_it()
    {
        var (https, alt) = (Info(), Info());
        MarkAndCheck([Device("192.168.1.1", (443, https), (8443, alt))]);

        Assert.Empty(https.SharedWith);
        Assert.Empty(alt.SharedWith);
    }

    [Fact]
    public void A_certificate_from_an_authority_on_several_servers_is_normal()
    {
        var (a, b) = (Info(x => x.SelfSigned = false), Info(x => x.SelfSigned = false));
        MarkAndCheck([Device("192.168.1.10", (443, a)), Device("192.168.1.11", (443, b))]);

        Assert.Empty(a.SharedWith);
        Assert.Empty(TlsAnalyzer.Analyze(a, 443, Now));
    }

    [Fact]
    public void Three_devices_list_the_other_two()
    {
        var (a, b, c) = (Info(), Info(), Info());
        MarkAndCheck([Device("192.168.1.1", (443, a)), Device("192.168.1.2", (443, b)), Device("192.168.1.3", (443, c))]);

        Assert.Equal(["192.168.1.2", "192.168.1.3"], a.SharedWith);
        Assert.Equal(["192.168.1.1", "192.168.1.3"], b.SharedWith);
    }
}
