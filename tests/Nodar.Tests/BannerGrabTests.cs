using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetworkScanner.Services;
using NetworkScanner.Services.Vulnerabilities;

namespace Nodar.Tests;

/// <summary>Testes da leitura de banners contra servidores locais (loopback).</summary>
public sealed class BannerGrabTests : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _serverCts = new(TimeSpan.FromSeconds(20));

    public BannerGrabTests() => _listener.Start();

    private int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public void Dispose()
    {
        _serverCts.Cancel();
        _listener.Stop();
        _serverCts.Dispose();
    }

    private ServiceDetectionService.BannerGrabOptions Options(bool http = false, bool tls = false) => new()
    {
        ConnectTimeout = TimeSpan.FromSeconds(2),
        FirstReadTimeout = TimeSpan.FromMilliseconds(400),
        IdleReadTimeout = TimeSpan.FromMilliseconds(400),
        HttpPorts = http ? new HashSet<int> { Port } : new HashSet<int>(),
        TlsPorts = tls ? new HashSet<int> { Port } : new HashSet<int>()
    };

    /// <summary>Aceita uma ligação e corre <paramref name="handler"/> sobre ela.</summary>
    private Task Serve(Func<Stream, CancellationToken, Task> handler) => Task.Run(async () =>
    {
        using var client = await _listener.AcceptTcpClientAsync(_serverCts.Token);
        await using var stream = client.GetStream();
        await handler(stream, _serverCts.Token);
    });

    private static async Task<string> ReadRequestHeadAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[4096];
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total), ct);
            if (n == 0) break;
            total += n;
            if (Encoding.ASCII.GetString(buffer, 0, total).Contains("\r\n\r\n")) break;
        }
        return Encoding.ASCII.GetString(buffer, 0, total);
    }

    [Fact]
    public async Task Silent_server_times_out_instead_of_hanging()
    {
        // Servidor que aceita e nunca responde (como SMB/RDP à espera do cliente).
        var server = Serve(async (_, ct) => await Task.Delay(TimeSpan.FromSeconds(10), ct).ContinueWith(_ => { }));

        var sw = Stopwatch.StartNew();
        var banner = await ServiceDetectionService.GrabBannerAsync("127.0.0.1", Port, CancellationToken.None, Options());
        sw.Stop();

        Assert.Equal("", banner);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3), $"demorou {sw.Elapsed}");
    }

    [Fact]
    public async Task Http_headers_split_across_packets_are_read_completely()
    {
        string? request = null;
        var server = Serve(async (s, ct) =>
        {
            request = await ReadRequestHeadAsync(s, ct);
            await s.WriteAsync("HTTP/1.1 200 OK\r\nDate: x\r\n"u8.ToArray(), ct);
            await s.FlushAsync(ct);
            await Task.Delay(150, ct);
            await s.WriteAsync("Server: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"u8.ToArray(), ct);
            await Task.Delay(TimeSpan.FromSeconds(5), ct).ContinueWith(_ => { }); // mantém ligação aberta
        });

        var sw = Stopwatch.StartNew();
        var banner = await ServiceDetectionService.GrabBannerAsync("127.0.0.1", Port, CancellationToken.None, Options(http: true));
        sw.Stop();

        Assert.Contains("Server: nginx/1.24.0", banner);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), "deve parar no fim dos cabeçalhos, sem esperar o fecho");
        Assert.StartsWith("GET / HTTP/1.1\r\n", request);
        Assert.Contains("Host: 127.0.0.1", request);

        var parsed = BannerParser.Parse(banner, 80);
        Assert.Equal("nginx", parsed!.ProductKey);
        Assert.Equal("1.24.0", parsed.Version);
    }

    [Fact]
    public async Task Https_banner_is_read_over_tls_with_self_signed_certificate()
    {
        using var certificate = CreateSelfSignedCertificate();
        var server = Task.Run(async () =>
        {
            using var client = await _listener.AcceptTcpClientAsync(_serverCts.Token);
            await using var ssl = new SslStream(client.GetStream());
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, _serverCts.Token);
            await ReadRequestHeadAsync(ssl, _serverCts.Token);
            await ssl.WriteAsync("HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.59\r\n\r\n"u8.ToArray(), _serverCts.Token);
            await ssl.FlushAsync(_serverCts.Token);
            await Task.Delay(TimeSpan.FromSeconds(5), _serverCts.Token).ContinueWith(_ => { });
        });

        var banner = await ServiceDetectionService.GrabBannerAsync("127.0.0.1", Port, CancellationToken.None, Options(http: true, tls: true));

        var parsed = BannerParser.Parse(banner, 443);
        Assert.Equal("lighttpd", parsed!.ProductKey);
        Assert.Equal("1.4.59", parsed.Version);
    }

    [Fact]
    public async Task Tls_port_falls_back_to_plain_http()
    {
        // 1.ª ligação: o cliente tenta TLS, o servidor (HTTP simples) não percebe e fecha.
        // 2.ª ligação: HTTP simples.
        var server = Task.Run(async () =>
        {
            using (var first = await _listener.AcceptTcpClientAsync(_serverCts.Token))
            {
                var buffer = new byte[1024];
                _ = await first.GetStream().ReadAsync(buffer, _serverCts.Token);
            }
            using var second = await _listener.AcceptTcpClientAsync(_serverCts.Token);
            var s = second.GetStream();
            await ReadRequestHeadAsync(s, _serverCts.Token);
            await s.WriteAsync("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n\r\n"u8.ToArray(), _serverCts.Token);
            await Task.Delay(TimeSpan.FromSeconds(5), _serverCts.Token).ContinueWith(_ => { });
        });

        var banner = await ServiceDetectionService.GrabBannerAsync("127.0.0.1", Port, CancellationToken.None, Options(http: true, tls: true));
        Assert.Contains("Apache/2.4.58", banner);
    }

    [Fact]
    public async Task Server_first_protocols_receive_nothing_from_the_client()
    {
        // IMAP/POP3/FTP/SMTP: o cliente nunca deve enviar comandos (sobretudo login).
        var received = -1;
        var server = Serve(async (s, ct) =>
        {
            await s.WriteAsync("* OK IMAP4rev1 ready\r\n"u8.ToArray(), ct);
            await s.FlushAsync(ct);
            var buffer = new byte[256];
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(TimeSpan.FromMilliseconds(800));
            try { received = await s.ReadAsync(buffer, wait.Token); }
            catch (OperationCanceledException) { received = 0; }
        });

        var banner = await ServiceDetectionService.GrabBannerAsync("127.0.0.1", Port, CancellationToken.None, Options());
        await server;

        Assert.StartsWith("* OK", banner);
        Assert.Equal(0, received);
    }

    [Fact]
    public async Task User_cancellation_propagates()
    {
        var server = Serve(async (_, ct) => await Task.Delay(TimeSpan.FromSeconds(10), ct).ContinueWith(_ => { }));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var slow = Options() with { FirstReadTimeout = TimeSpan.FromSeconds(10) };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ServiceDetectionService.GrabBannerAsync("127.0.0.1", Port, cts.Token, slow));
    }

    [Fact]
    public async Task Closed_port_returns_empty()
    {
        var port = Port;
        _listener.Stop();
        var banner = await ServiceDetectionService.GrabBannerAsync("127.0.0.1", port, CancellationToken.None, Options());
        Assert.Equal("", banner);
    }

    private static X509Certificate2 CreateSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=nodar-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        // No Windows o SChannel precisa de uma chave importada (não efémera).
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
    }
}
