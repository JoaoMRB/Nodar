using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkScanner.Models;

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
                    var versionInfo = ParseBannerForVersion(banner, serviceName);
                    serviceInfo.Version = versionInfo.Version;
                    serviceInfo.Product = versionInfo.Product;
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
            3306 => new byte[] { }, // MySQL (no probe needed)
            5432 => new byte[] { }, // PostgreSQL (no probe needed)
            6379 => Encoding.ASCII.GetBytes("PING\r\n"), // Redis
            _ => null
        };
    }

    private static (string Product, string Version) ParseBannerForVersion(string banner, string serviceName)
    {
        if (string.IsNullOrEmpty(banner))
            return ("", "");

        var product = "";
        var version = "";

        // SSH banners
        if (serviceName == "SSH" && banner.StartsWith("SSH-"))
        {
            var parts = banner.Split(' ');
            if (parts.Length >= 2)
            {
                product = parts[1].Split('-')[0];
                version = parts[1].Split('-').Length > 1 ? parts[1].Split('-')[1] : "";
            }
        }
        // HTTP banners
        else if (serviceName == "HTTP" || serviceName == "HTTPS")
        {
            if (banner.Contains("Server:"))
            {
                var serverLine = banner.Split('\n').FirstOrDefault(l => l.StartsWith("Server:"));
                if (serverLine != null)
                {
                    var serverInfo = serverLine.Replace("Server:", "").Trim();
                    var parts = serverInfo.Split('/');
                    if (parts.Length >= 1)
                    {
                        product = parts[0].Trim();
                        version = parts.Length > 1 ? parts[1].Trim() : "";
                    }
                }
            }
        }
        // FTP banners
        else if (serviceName == "FTP" && banner.Contains("220"))
        {
            var parts = banner.Split(' ');
            if (parts.Length >= 3)
            {
                product = parts[2];
                version = parts.Length > 3 ? parts[3] : "";
            }
        }
        // SMTP banners
        else if (serviceName == "SMTP" && banner.Contains("220"))
        {
            var parts = banner.Split(' ');
            if (parts.Length >= 3)
            {
                product = parts[2];
                version = parts.Length > 3 ? parts[3] : "";
            }
        }
        // MySQL
        else if (serviceName == "MySQL")
        {
            if (banner.Contains("mysql"))
            {
                product = "MySQL";
                var match = System.Text.RegularExpressions.Regex.Match(banner, @"(\d+\.\d+\.\d+)");
                if (match.Success)
                {
                    version = match.Value;
                }
            }
        }
        // Redis
        else if (serviceName == "Redis")
        {
            if (banner.Contains("redis"))
            {
                product = "Redis";
                var match = System.Text.RegularExpressions.Regex.Match(banner, @"(\d+\.\d+\.\d+)");
                if (match.Success)
                {
                    version = match.Value;
                }
            }
        }

        return (product, version);
    }

    public static async Task<List<Models.VulnerabilityInfo>> CheckVulnerabilitiesAsync(List<Models.ServiceInfo> services, CancellationToken ct = default)
    {
        var vulnerabilities = new List<Models.VulnerabilityInfo>();

        foreach (var service in services)
        {
            ct.ThrowIfCancellationRequested();

            var serviceVulns = CheckServiceVulnerabilities(service);
            vulnerabilities.AddRange(serviceVulns);
        }

        return vulnerabilities;
    }

    private static List<Models.VulnerabilityInfo> CheckServiceVulnerabilities(Models.ServiceInfo service)
    {
        var vulns = new List<Models.VulnerabilityInfo>();

        // Use expanded vulnerability database
        var dbVulns = VulnerabilityDatabase.GetVulnerabilitiesForService(service.Service, service.Version);
        
        foreach (var dbVuln in dbVulns)
        {
            vulns.Add(new Models.VulnerabilityInfo
            {
                Service = dbVuln.Service,
                Severity = dbVuln.Severity,
                CVE = dbVuln.CVE,
                Description = dbVuln.Description
            });
        }

        return vulns;
    }

    private static bool IsOldVersion(string version, string minimumVersion)
    {
        try
        {
            var current = Version.Parse(version);
            var minimum = Version.Parse(minimumVersion);
            return current < minimum;
        }
        catch
        {
            return false;
        }
    }
}

public class VulnerabilityInfo
{
    public string Service { get; set; } = "";
    public string Severity { get; set; } = "";
    public string CVE { get; set; } = "";
    public string Description { get; set; } = "";
}
