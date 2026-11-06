using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Nodar.Core.Models;
using Nodar.Core.Services.Vulnerabilities;

namespace Nodar.Core.Services;

public static class ServiceDetectionService
{

    private static readonly Dictionary<int, string> CommonServices = new()
    {
        [21] = "FTP",
        [22] = "SSH",
        [23] = "Telnet",
        [25] = "SMTP",
        [53] = "DNS",
        [80] = "HTTP",
        [110] = "POP3",
        [135] = "MSRPC",
        [139] = "NetBIOS",
        [143] = "IMAP",
        [443] = "HTTPS",
        [445] = "SMB",
        [993] = "IMAPS",
        [995] = "POP3S",
        [1433] = "MSSQL",
        [1521] = "Oracle",
        [3306] = "MySQL",
        [3389] = "RDP",
        [5432] = "PostgreSQL",
        [5900] = "VNC",
        [6379] = "Redis",
        [8080] = "HTTP-Alt",
        [8443] = "HTTPS-Alt",
        [8888] = "HTTP-Alt",
        [5000] = "HTTP-Alt",
        [8000] = "HTTP-Alt",
        [7547] = "TR-069",
        [49152] = "UPnP"
    };

    /// <summary>Nome do serviço habitual numa porta (<c>null</c> se não for uma das conhecidas).</summary>
    public static string? WellKnownName(int port) => CommonServices.GetValueOrDefault(port);

    public static async Task<List<Models.ServiceInfo>> DetectServicesAsync(string ip, List<int> openPorts, CancellationToken ct = default)
    {
        var services = new List<Models.ServiceInfo>();

        foreach (var port in openPorts)
        {
            ct.ThrowIfCancellationRequested();

            // Create service info based on port number (no need to reconnect)
            var serviceName = CommonServices.GetValueOrDefault(port, "unknown");
            
            var serviceInfo = new Models.ServiceInfo
            {
                Port = port,
                Service = serviceName,
                Version = "",
                Product = "",
                Banner = ""
            };

            // Try to get banner for version info (best effort)
            try
            {
                // DNS: a versão obtém-se por consulta UDP (version.bind), não por banner TCP.
                var banner = port == 53
                    ? (await DnsVersionProbe.QueryAsync(ip, ct)) is { } dnsVersion
                        ? DnsVersionProbe.BannerPrefix + dnsVersion
                        : ""
                    : await GrabBannerAsync(ip, port, ct);
                if (!string.IsNullOrEmpty(banner))
                    serviceInfo = FromBanner(port, serviceName, banner);
            }
            catch (Exception ex) when (NodarLog.Swallow(ex, "Leitura de banner", ct))
            {
                // Sem banner, mas o serviço continua conhecido pelo número da porta. O cancelamento do
                // utilizador não é engolido aqui (antes era: o "Parar" podia ser ignorado neste ponto).
            }

            services.Add(serviceInfo);
        }

        return services;
    }


    /// <summary>Serviço a partir de um banner já obtido (TCP, DNS version.bind, cabeçalho SSDP…).</summary>
    public static Models.ServiceInfo FromBanner(int port, string serviceName, string banner)
    {
        var service = new Models.ServiceInfo { Port = port, Service = serviceName, Banner = banner };
        var parsed = BannerParser.Parse(banner, port);
        if (parsed != null)
        {
            service.ProductKey = parsed.ProductKey;
            service.Product = parsed.ProductName;
            service.Version = parsed.Version;
            service.IsDistroPackage = parsed.IsDistroPackage;
            service.DistroName = parsed.DistroName;
        }
        return service;
    }

    /// <summary>Opções da leitura de banners (configuráveis para testes).</summary>
    public sealed record BannerGrabOptions
    {
        public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(2);

        /// <summary>Tempo máximo à espera dos primeiros bytes.</summary>
        public TimeSpan FirstReadTimeout { get; init; } = TimeSpan.FromSeconds(3);

        /// <summary>Tempo de espera por mais dados depois de já ter recebido alguns.</summary>
        public TimeSpan IdleReadTimeout { get; init; } = TimeSpan.FromMilliseconds(500);

        public int MaxBytes { get; init; } = 4096;

        /// <summary>Portas onde se tenta TLS primeiro (com recurso a texto simples se o TLS falhar).</summary>
        public IReadOnlySet<int> TlsPorts { get; init; } = new HashSet<int> { 443, 8443 };

        /// <summary>Portas que recebem um pedido HTTP.</summary>
        public IReadOnlySet<int> HttpPorts { get; init; } =
            new HashSet<int> { 80, 443, 5000, 7547, 8000, 8080, 8443, 8888, 49152 };

        public static BannerGrabOptions Default { get; } = new();
    }

    /// <summary>
    /// Lê o banner de um serviço. Nunca bloqueia indefinidamente: cada fase tem timeout.
    /// Em portas TLS faz o handshake e lê o cabeçalho HTTP por cima da ligação cifrada.
    /// </summary>
    /// <remarks>
    /// As sondas são passivas ou pedidos anónimos (HTTP GET, identificação SSH, Redis INFO).
    /// Nunca são enviadas credenciais nem tentativas de login.
    /// </remarks>
    public static async Task<string> GrabBannerAsync(string ip, int port, CancellationToken ct, BannerGrabOptions? options = null)
    {
        options ??= BannerGrabOptions.Default;

        if (options.TlsPorts.Contains(port))
        {
            var tls = await TryGrabAsync(ip, port, useTls: true, options, ct);
            if (!string.IsNullOrEmpty(tls))
                return tls;
            // Algumas portas "HTTPS" (sobretudo 8443) servem HTTP simples.
        }

        return await TryGrabAsync(ip, port, useTls: false, options, ct);
    }

    private static async Task<string> TryGrabAsync(string ip, int port, bool useTls, BannerGrabOptions options, CancellationToken ct)
    {
        using var client = new TcpClient();
        try
        {
            using (var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connectTimeout.CancelAfter(options.ConnectTimeout);
                await client.ConnectAsync(IPAddress.Parse(ip), port, connectTimeout.Token);
            }

            Stream stream = client.GetStream();
            if (useTls)
            {
                // O certificado não é validado de propósito: só se lê o cabeçalho "Server" e nada
                // sensível é enviado. Routers e dispositivos IoT usam quase sempre certificados autoassinados.
                var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                using var handshakeTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                handshakeTimeout.CancelAfter(options.FirstReadTimeout);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = ip,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, handshakeTimeout.Token);
                stream = ssl;
            }

            await using (stream)
            {
                var isHttp = options.HttpPorts.Contains(port);
                var probe = GetServiceProbe(port, ip, isHttp);
                if (probe is { Length: > 0 })
                    await stream.WriteAsync(probe, ct);

                return await ReadBannerAsync(stream, isHttp, options, ct);
            }
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, $"Banner da porta {port}", ct))
        {
            return ""; // timeout, ligação recusada, TLS falhou, etc.
        }
    }

    /// <summary>
    /// Lê até ao fim dos cabeçalhos (HTTP), até <see cref="BannerGrabOptions.MaxBytes"/>,
    /// até o servidor fechar ou até deixar de chegar dados.
    /// </summary>
    private static async Task<string> ReadBannerAsync(Stream stream, bool isHttp, BannerGrabOptions options, CancellationToken ct)
    {
        var buffer = new byte[options.MaxBytes];
        var total = 0;

        while (total < buffer.Length)
        {
            using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readTimeout.CancelAfter(total == 0 ? options.FirstReadTimeout : options.IdleReadTimeout);

            int read;
            try
            {
                read = await stream.ReadAsync(buffer.AsMemory(total), readTimeout.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                break; // sem mais dados dentro do prazo
            }
            catch (IOException)
            {
                break; // ligação fechada a meio
            }

            if (read == 0)
                break;
            total += read;

            if (isHttp && buffer.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0)
                break; // cabeçalhos completos; o corpo não interessa
        }

        // Latin-1 preserva cada byte (ASCII perderia os bytes binários do handshake MySQL).
        return Encoding.Latin1.GetString(buffer, 0, total);
    }

    private static byte[]? GetServiceProbe(int port, string ip, bool isHttp)
    {
        if (isHttp)
            return Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Nodar\r\nAccept: */*\r\nConnection: close\r\n\r\n");

        return port switch
        {
            22 => Encoding.ASCII.GetBytes("SSH-2.0-Nodar\r\n"),
            6379 => Encoding.ASCII.GetBytes("INFO server\r\n"), // devolve redis_version (PING não tem versão)
            // FTP, SMTP, POP3, IMAP, MySQL, VNC…: o servidor fala primeiro, não é preciso enviar nada.
            // (Enviar EHLO antes da saudação faz o Postfix/postscreen tratar o cliente como spammer.)
            _ => null
        };
    }
}
