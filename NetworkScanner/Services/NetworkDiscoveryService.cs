using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using NetworkScanner.Models;
using NetworkScanner.Services;

namespace NetworkScanner.Services;

public static class NetworkDiscoveryService
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] pMacAddr, ref int phyAddrLen);

    private static readonly int[] CommonPorts =
    [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        3306, 3389, 5000, 5900, 8000, 8080, 8443, 8888
    ];

    public static LocalNetworkInfo? GetLocalNetwork()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
                continue;

            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback
                or NetworkInterfaceType.Tunnel)
                continue;

            var name = nic.Name + nic.Description;
            if (IsVirtualAdapter(name))
                continue;

            var ipv4 = nic.GetIPProperties().UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

            if (ipv4 == null)
                continue;

            var gateway = nic.GetIPProperties().GatewayAddresses
                .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?
                .Address.ToString() ?? "";

            if (string.IsNullOrEmpty(gateway))
                continue;

            var ip = ipv4.Address.ToString();
            var mask = ipv4.IPv4Mask.ToString();
            var network = CalculateNetwork(ip, mask);
            var mac = FormatMac(nic.GetPhysicalAddress().GetAddressBytes());

            return new LocalNetworkInfo
            {
                InterfaceName = nic.Name,
                IpAddress = ip,
                SubnetMask = mask,
                Gateway = gateway,
                NetworkRange = network,
                Hostname = Dns.GetHostName(),
                MacAddress = mac
            };
        }

        return null;
    }

    public static async Task<ScanResult> ScanAsync(ScanOptions options)
    {
        var stopwatch = Stopwatch.StartNew();
        var network = GetLocalNetwork();

        if (network == null)
        {
            return new ScanResult
            {
                Error = "Não foi possível detetar a rede local. Verifica a ligação Wi-Fi/Ethernet.",
                Duration = stopwatch.Elapsed
            };
        }

        options.Progress?.Report(new ScanProgress
        {
            Percent = 5,
            Message = "A ler tabela ARP...",
            DevicesFound = 0
        });

        var arpTable = ParseArpTable();
        var discovered = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var method = "ARP";

        foreach (var (ip, mac) in arpTable)
        {
            if (!IsInNetwork(ip, network.IpAddress, network.SubnetMask))
                continue;

            if (ip == network.Gateway || ip == network.IpAddress || await ProbeHostAsync(ip, 180))
                discovered[ip] = mac;
        }

        if (!string.IsNullOrWhiteSpace(network.Gateway))
        {
            discovered[network.Gateway] = ResolveMac(network.Gateway);
        }

        var hostRange = GetHostRange(network.IpAddress, network.SubnetMask);
        var rangeSize = hostRange.Count;
        var shouldSweep = options.DeepScan || rangeSize <= 256 || discovered.Count < 5;

        if (shouldSweep)
        {
            options.Progress?.Report(new ScanProgress
            {
                Percent = 15,
                Message = "A verificar hosts próximos...",
                DevicesFound = discovered.Count
            });

            var aliveHosts = await FastPingSweepAsync(network, options);
            method = discovered.Count > 0 ? "ARP + Ping" : "Ping";

            foreach (var ip in aliveHosts)
            {
                if (!discovered.ContainsKey(ip))
                    discovered[ip] = ResolveMac(ip);
            }
        }

        if (!string.IsNullOrWhiteSpace(network.Gateway))
        {
            var gateway = network.Gateway;
            if (!discovered.ContainsKey(gateway) && await PingHostAsync(gateway))
            {
                discovered[gateway] = ResolveMac(gateway);
            }
        }

        if (!discovered.ContainsKey(network.IpAddress))
            discovered[network.IpAddress] = network.MacAddress;

        var total = discovered.Count;
        var processed = 0;
        var devices = new List<DeviceInfo>();

        foreach (var (ip, mac) in discovered.OrderBy(d => d.Key == network.Gateway ? 0 : 1).ThenBy(d => IpToUInt(d.Key)))
        {
            options.CancellationToken.ThrowIfCancellationRequested();

            processed++;
            var percent = 30 + (int)(processed / (double)Math.Max(total, 1) * 60);

            options.Progress?.Report(new ScanProgress
            {
                Percent = percent,
                Message = $"A analisar {ip}...",
                DevicesFound = devices.Count
            });

            var hostname = await ResolveHostnameAsync(ip);
            var vendor = VendorService.Lookup(mac);
            var openPorts = "";
            var operatingSystem = "";
            var osConfidence = "";
            var services = new List<Models.ServiceInfo>();
            var vulnerabilities = new List<Models.VulnerabilityInfo>();

            if (ip == network.Gateway)
            {
                vendor = string.IsNullOrWhiteSpace(vendor) || vendor == "Desconhecido"
                    ? "Router/Gateway"
                    : vendor;
                if (string.IsNullOrWhiteSpace(hostname))
                    hostname = "router";
            }

            if (options.PortScan && ip != network.Gateway)
            {
                var ports = await ScanPortsAsync(ip, options.CancellationToken);
                openPorts = ports.Count > 0 ? string.Join(", ", ports) : "";

                // Service detection
                if (options.ServiceDetection && ports.Count > 0)
                {
                    services = await ServiceDetectionService.DetectServicesAsync(ip, ports, options.CancellationToken);
                    
                    // Vulnerability scanning
                    if (options.VulnerabilityScan)
                    {
                        vulnerabilities = await ServiceDetectionService.CheckVulnerabilitiesAsync(services, options.CancellationToken);
                    }
                }
            }

            // OS Detection
            if (options.OSDetection && ip != network.Gateway)
            {
                var osResult = await OSFingerprintService.DetectOSAsync(ip, options.CancellationToken);
                operatingSystem = osResult.LikelyOS;
                osConfidence = osResult.Confidence;
            }

            devices.Add(new DeviceInfo
            {
                IpAddress = ip,
                MacAddress = string.IsNullOrEmpty(mac) ? "—" : VendorService.NormalizeMac(mac),
                Hostname = hostname,
                Vendor = vendor,
                Status = "Online",
                OpenPorts = openPorts,
                IsLocalDevice = ip == network.IpAddress,
                DeviceType = VendorService.GetDeviceType(vendor, hostname),
                LastSeen = DateTime.Now,
                OperatingSystem = operatingSystem,
                OSConfidence = osConfidence,
                Services = services,
                Vulnerabilities = vulnerabilities
            });
        }

        options.Progress?.Report(new ScanProgress
        {
            Percent = 100,
            Message = "Análise concluída",
            DevicesFound = devices.Count
        });

        stopwatch.Stop();

        return new ScanResult
        {
            Network = network,
            Devices = devices.OrderByDescending(d => d.IsLocalDevice)
                .ThenBy(d => IpToUInt(d.IpAddress))
                .ToList(),
            ScanMethod = method,
            Duration = stopwatch.Elapsed
        };
    }

    public static bool IsAdministrator()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsVirtualAdapter(string name)
    {
        var lower = name.ToLowerInvariant();
        string[] blocked =
        [
            "virtual", "vmware", "hyper-v", "vethernet", "bluetooth",
            "loopback", "tunnel", "wsl", "docker", "vpn", "tap", "tun",
            "pseudo", "filter", "miniport", "npcap"
        ];
        return blocked.Any(lower.Contains);
    }

    private static string CalculateNetwork(string ip, string mask)
    {
        var ipBytes = IPAddress.Parse(ip).GetAddressBytes();
        var maskBytes = IPAddress.Parse(mask).GetAddressBytes();
        var network = new byte[4];

        for (var i = 0; i < 4; i++)
            network[i] = (byte)(ipBytes[i] & maskBytes[i]);

        var prefix = CountMaskBits(maskBytes);
        return $"{network[0]}.{network[1]}.{network[2]}.{network[3]}/{prefix}";
    }

    private static int CountMaskBits(byte[] mask)
    {
        var count = 0;
        foreach (var b in mask)
            count += Convert.ToString(b, 2).Count(c => c == '1');
        return count;
    }

    private static bool IsInNetwork(string ip, string localIp, string mask)
    {
        try
        {
            var ipBytes = IPAddress.Parse(ip).GetAddressBytes();
            var localBytes = IPAddress.Parse(localIp).GetAddressBytes();
            var maskBytes = IPAddress.Parse(mask).GetAddressBytes();

            for (var i = 0; i < 4; i++)
            {
                if ((ipBytes[i] & maskBytes[i]) != (localBytes[i] & maskBytes[i]))
                    return false;
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static Dictionary<string, string> ParseArpTable()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var psi = new ProcessStartInfo("arp", "-a")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return result;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            var regex = new Regex(@"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", RegexOptions.Compiled);
            foreach (Match match in regex.Matches(output))
            {
                var ip = match.Groups[1].Value;
                var mac = VendorService.NormalizeMac(match.Groups[2].Value);

                if (ip.StartsWith("224.") || ip.StartsWith("239.") || mac == "FF:FF:FF:FF:FF:FF")
                    continue;

                result[ip] = mac;
            }
        }
        catch { }

        return result;
    }

    private static async Task<List<string>> FastPingSweepAsync(LocalNetworkInfo network, ScanOptions options)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var gateway = network.Gateway;

        foreach (var candidate in GetLikelyRouterCandidates(network))
        {
            if (!string.IsNullOrWhiteSpace(candidate))
                hosts.Add(candidate);
        }

        if (!string.IsNullOrWhiteSpace(gateway))
            hosts.Add(gateway);

        var hostRange = GetHostRange(network.IpAddress, network.SubnetMask);
        var rangeSize = hostRange.Count;

        if (rangeSize <= 256)
        {
            foreach (var ip in hostRange)
                hosts.Add(ip);
        }
        else
        {
            foreach (var ip in hostRange.Take(50))
                hosts.Add(ip);

            foreach (var ip in hostRange.Skip(Math.Max(0, rangeSize - 50)))
                hosts.Add(ip);

            var step = Math.Max(1, rangeSize / 20);
            for (var i = 0; i < 20; i++)
            {
                var index = Math.Min(rangeSize - 1, i * step);
                hosts.Add(hostRange[index]);
            }

            foreach (var candidate in GetLikelyRouterCandidates(network))
                hosts.Add(candidate);
        }

        var alive = new System.Collections.Concurrent.ConcurrentBag<string>();

        await Parallel.ForEachAsync(hosts.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase), new ParallelOptions
        {
            MaxDegreeOfParallelism = 16,
            CancellationToken = options.CancellationToken
        }, async (ip, ct) =>
        {
            if (await ProbeHostAsync(ip, 350))
                alive.Add(ip);
        });

        return alive.OrderBy(IpToUInt).ToList();
    }

    private static async Task<bool> ProbeHostAsync(string ip, int timeout = 350)
    {
        var hasMac = !string.IsNullOrWhiteSpace(ResolveMac(ip));
        var hasPing = await PingHostAsync(ip, timeout);
        
        return hasPing && hasMac;
    }

    private static List<string> GetLikelyRouterCandidates(LocalNetworkInfo network)
    {
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var gatewayBytes = IPAddress.Parse(network.Gateway).GetAddressBytes();
            var lastOctet = gatewayBytes[3];

            foreach (var octet in new[] { 1, 2, 10, 11, 20, 30, 50, 100, 200, 254 })
            {
                var bytes = gatewayBytes.ToArray();
                bytes[3] = (byte)octet;
                candidates.Add(new IPAddress(bytes).ToString());
            }

            if (lastOctet != 1)
                candidates.Add(new IPAddress(new byte[] { gatewayBytes[0], gatewayBytes[1], gatewayBytes[2], 1 }).ToString());
            if (lastOctet != 254)
                candidates.Add(new IPAddress(new byte[] { gatewayBytes[0], gatewayBytes[1], gatewayBytes[2], 254 }).ToString());
        }
        catch
        {
            // Ignorar se o gateway não for válido.
        }

        return candidates.ToList();
    }

    private static List<string> GetHostRange(string ip, string mask)
    {
        var ipBytes = IPAddress.Parse(ip).GetAddressBytes();
        var maskBytes = IPAddress.Parse(mask).GetAddressBytes();
        var start = IpToUInt(ip) & IpToUInt(mask);
        var end = start | ~IpToUInt(mask);
        var hosts = new List<string>();

        for (var addr = start + 1; addr < end; addr++)
        {
            var bytes = new byte[4];
            bytes[0] = (byte)((addr >> 24) & 0xFF);
            bytes[1] = (byte)((addr >> 16) & 0xFF);
            bytes[2] = (byte)((addr >> 8) & 0xFF);
            bytes[3] = (byte)(addr & 0xFF);
            hosts.Add(new IPAddress(bytes).ToString());
        }

        return hosts;
    }

    private static async Task<bool> PingHostAsync(string ip, int timeout = 500)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, timeout);
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> IsHostActiveAsync(string ip, int timeout = 180)
    {
        return await ProbeHostAsync(ip, timeout);
    }

    private static string ResolveMac(string ip)
    {
        try
        {
            var dest = BitConverter.ToInt32(IPAddress.Parse(ip).GetAddressBytes(), 0);
            var mac = new byte[6];
            var len = mac.Length;

            if (SendARP(dest, 0, mac, ref len) == 0)
                return FormatMac(mac);
        }
        catch { }

        return "";
    }

    private static async Task<string> ResolveHostnameAsync(string ip)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            return entry.HostName != ip ? entry.HostName : "";
        }
        catch
        {
            return "";
        }
    }

    private static async Task<List<int>> ScanPortsAsync(string ip, CancellationToken ct)
    {
        var open = new System.Collections.Concurrent.ConcurrentBag<int>();

        await Parallel.ForEachAsync(CommonPorts, new ParallelOptions
        {
            MaxDegreeOfParallelism = 16,
            CancellationToken = ct
        }, async (port, token) =>
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(IPAddress.Parse(ip), port, token).AsTask();
                var completed = await Task.WhenAny(connectTask, Task.Delay(300, token));

                if (completed == connectTask && client.Connected)
                    open.Add(port);
            }
            catch { }
        });

        return open.OrderBy(p => p).ToList();
    }

    private static string FormatMac(byte[] bytes)
    {
        if (bytes.Length == 0) return "";
        return string.Join(':', bytes.Select(b => b.ToString("X2")));
    }

    private static uint IpToUInt(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        return ((uint)bytes[0] << 24) |
               ((uint)bytes[1] << 16) |
               ((uint)bytes[2] << 8) |
               bytes[3];
    }
}
