using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkScanner.Models;
using NetworkScanner.Services.Vulnerabilities;

namespace NetworkScanner.Services;

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
        [8888] = "HTTP-Alt"
    };

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
                var banner = await GrabBannerAsync(ip, port, ct);
                if (!string.IsNullOrEmpty(banner))
                {
                    serviceInfo.Banner = banner;
                    var parsed = BannerParser.Parse(banner, port);
                    if (parsed != null)
                    {
                        serviceInfo.ProductKey = parsed.ProductKey;
                        serviceInfo.Product = parsed.ProductName;
                        serviceInfo.Version = parsed.Version;
                        serviceInfo.IsDistroPackage = parsed.IsDistroPackage;
                        serviceInfo.DistroName = parsed.DistroName;
                    }
                }
            }
            catch
            {
                // Banner grab failed, but we still have service info from port number
            }

            services.Add(serviceInfo);
        }

        return services;
    }

    private static async Task<string> GrabBannerAsync(string ip, int port, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(IPAddress.Parse(ip), port, ct).AsTask();
            var completed = await Task.WhenAny(connectTask, Task.Delay(2000, ct));

            if (completed != connectTask || !client.Connected)
                return "";

            var stream = client.GetStream();
            var buffer = new byte[1024];
            
            // Send probe based on service type
            var probe = GetServiceProbe(port);
            if (probe != null)
            {
                await stream.WriteAsync(probe, 0, probe.Length, ct);
                await Task.Delay(500, ct);
            }

            var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, ct);
            if (bytesRead > 0)
            {
                return System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);
            }

            return "";
        }
        catch
        {
            return "";
        }
    }

    private static byte[]? GetServiceProbe(int port)
    {
        return port switch
        {
            21 => Encoding.ASCII.GetBytes("\r\n"), // FTP
            22 => Encoding.ASCII.GetBytes("SSH-2.0-Scanner\r\n"), // SSH
            25 => Encoding.ASCII.GetBytes("EHLO test\r\n"), // SMTP
            80 => Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: target\r\n\r\n"), // HTTP
            110 => Encoding.ASCII.GetBytes("USER test\r\n"), // POP3
            143 => Encoding.ASCII.GetBytes("A001 LOGIN test test\r\n"), // IMAP
            443 => Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: target\r\n\r\n"), // HTTPS
            5000 or 8000 or 8080 or 8888 => Encoding.ASCII.GetBytes("HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"), // HTTP alternativo
            3306 => new byte[] { }, // MySQL (no probe needed)
            5432 => new byte[] { }, // PostgreSQL (no probe needed)
            6379 => Encoding.ASCII.GetBytes("INFO server\r\n"), // Redis (devolve redis_version; PING não tem versão)
            _ => null
        };
    }

}
