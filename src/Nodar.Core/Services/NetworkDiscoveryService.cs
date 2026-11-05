using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Nodar.Core.Models;
using Nodar.Core.Services;

namespace Nodar.Core.Services;

public static class NetworkDiscoveryService
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] pMacAddr, ref int phyAddrLen);

    private static readonly int[] CommonPorts =
    [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        3306, 3389, 5000, 5900, 6379, 7547, 8000, 8080, 8443, 8888, 49152
        // 7547: TR-069/CWMP (gestão remota do operador em routers)
        // 49152: UPnP (miniupnpd e outros, comum em routers)
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

        var rangeSize = NeighborDiscovery.HostRange(network.IpAddress, network.SubnetMask).Count;
        options.Progress?.Report(new ScanProgress
        {
            Percent = 5,
            Message = $"A procurar dispositivos em {Math.Min(rangeSize, options.DeepScan ? int.MaxValue : NeighborDiscovery.FullSweepLimit)} endereços (ARP)...",
            DevicesFound = 0
        });

        // Registo oficial de fabricantes (IEEE): carrega da cache ou descarrega em paralelo com a descoberta.
        var ouiLoading = OuiRegistry.EnsureLoadedAsync(TimeSpan.FromSeconds(8), options.CancellationToken);

        // Presença decidida por ARP, sem exigir ping (iPhones, Macs e muitos outros ignoram ping).
        var neighbors = await NeighborDiscovery.DiscoverAsync(network, options.DeepScan, options.CancellationToken);
        var discovered = neighbors.Devices;
        var method = neighbors.PartialSweep ? $"ARP ({neighbors.AddressesSwept} endereços mais próximos)" : "ARP";

        if (!string.IsNullOrWhiteSpace(network.Gateway) && !discovered.ContainsKey(network.Gateway))
        {
            var gatewayMac = ResolveMac(network.Gateway);
            if (!string.IsNullOrEmpty(gatewayMac))
                discovered[network.Gateway] = gatewayMac;
        }

        if (!discovered.ContainsKey(network.IpAddress))
            discovered[network.IpAddress] = network.MacAddress;

        var total = discovered.Count;
        var processed = 0;
        var vulnerabilityService = options.VulnerabilityScan ? new Vulnerabilities.VulnerabilityService() : null;

        // Bonjour/mDNS: nome e modelo de Macs, iPhones, iPads, Chromecast, impressoras… (identifica
        // dispositivos com MAC privado, onde o fabricante não se sabe pelo MAC).
        // SSDP/UPnP: TVs, boxes, consolas e routers (nome, fabricante, modelo). NetBIOS: nome de PCs Windows.
        options.Progress?.Report(new ScanProgress { Percent = 20, Message = "A identificar dispositivos (Bonjour, UPnP, NetBIOS)…", DevicesFound = total });
        var ipList = discovered.Keys.ToList();
        var ipSet = ipList.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var mdnsTask = MdnsProbe.QueryAsync(ipList, options.CancellationToken);
        var ssdpTask = SsdpProbe.QueryAsync(ipSet.Contains, options.CancellationToken);
        var netbiosTask = NetBiosProbe.QueryAsync(ipList, options.CancellationToken);
        await Task.WhenAll(mdnsTask, ssdpTask, netbiosTask);
        await ouiLoading;
        var (mdns, ssdp, netbios) = (mdnsTask.Result, ssdpTask.Result, netbiosTask.Result);
        Clues CluesFor(string ip) => new(mdns.GetValueOrDefault(ip), ssdp.GetValueOrDefault(ip), netbios.GetValueOrDefault(ip));

        // Lista preliminar logo após a descoberta (a interface mostra-a enquanto os detalhes chegam).
        options.DevicesDiscovered?.Report(discovered
            .Select(d => BasicDevice(d.Key, d.Value, "", network, CluesFor(d.Key)))
            .ToList());

        options.Progress?.Report(new ScanProgress
        {
            Percent = 30,
            Message = $"{total} dispositivos encontrados · a identificar…",
            DevicesFound = total
        });

        // Vários dispositivos em paralelo: a maior parte do tempo é espera de rede (DNS, portas, banners).
        var analyzed = new System.Collections.Concurrent.ConcurrentBag<DeviceInfo>();
        await Parallel.ForEachAsync(
            discovered.OrderBy(d => d.Key == network.Gateway ? 0 : 1).ThenBy(d => IpToUInt(d.Key)),
            new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = options.CancellationToken },
            async (pair, ct) =>
            {
                analyzed.Add(await AnalyzeDeviceAsync(pair.Key, pair.Value, network, options, vulnerabilityService,
                    CluesFor(pair.Key), ct));
                var done = Interlocked.Increment(ref processed);
                options.Progress?.Report(new ScanProgress
                {
                    Percent = 30 + (int)(done / (double)Math.Max(total, 1) * 65),
                    Message = $"A identificar dispositivos ({done}/{total})…",
                    DevicesFound = total
                });
            });
        var devices = analyzed.ToList();

        // Entradas que vinham só da cache ARP e que o sistema entretanto deu como inalcançáveis: já saíram.
        var gone = NeighborDiscovery.GoneSince(neighbors.Unconfirmed);
        gone.Remove(network.Gateway);
        gone.Remove(network.IpAddress);
        if (gone.Count > 0)
            devices.RemoveAll(d => gone.Contains(d.IpAddress));

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
            Duration = stopwatch.Elapsed,
            VulnerabilitySourceNote = vulnerabilityService?.BuildSourceNote()
        };
    }

    private static string VendorFor(string mac, string ip, LocalNetworkInfo network)
    {
        var vendor = VendorService.Lookup(mac);
        // iPhone, Android, Windows e macOS usam MACs privados (aleatórios) por rede Wi-Fi: não há fabricante.
        if ((string.IsNullOrWhiteSpace(vendor) || vendor == "Desconhecido") && NeighborDiscovery.IsRandomizedMac(mac))
            vendor = VendorService.PrivateAddressVendor;
        if (ip == network.Gateway && (string.IsNullOrWhiteSpace(vendor) || vendor == "Desconhecido"))
            vendor = "Router/Gateway";
        return vendor;
    }

    /// <summary>O que os protocolos de identificação disseram sobre um IP.</summary>
    private sealed record Clues(MdnsProbe.Identity? Mdns, SsdpProbe.Identity? Ssdp, NetBiosProbe.Names? NetBios);

    private static DeviceInfo BasicDevice(string ip, string mac, string hostname, LocalNetworkInfo network, Clues clues)
    {
        var vendor = VendorFor(mac, ip, network);
        var identity = clues.Mdns;
        var described = DeviceIdentification.Combine(clues.Mdns, clues.Ssdp, clues.NetBios);

        // Hostname: o do DNS do router, ou o .local do Bonjour se o do router não disser nada (ex.: o MAC).
        if (DeviceIdentification.IsMeaninglessHostname(hostname) && !string.IsNullOrWhiteSpace(identity?.Hostname)
            && !DeviceIdentification.IsMeaninglessHostname(identity.Hostname))
            hostname = identity.Hostname!;
        if (DeviceIdentification.IsMeaninglessHostname(hostname) && !string.IsNullOrWhiteSpace(clues.NetBios?.ComputerName))
            hostname = clues.NetBios.ComputerName!;
        if (DeviceIdentification.IsMeaninglessHostname(hostname))
            hostname = "";

        // Fabricante anunciado (descritor UPnP, modelo Apple) é mais fiável do que o do MAC (muitas vezes o do chip Wi-Fi).
        if (!string.IsNullOrWhiteSpace(described?.Vendor))
            vendor = described.Vendor!;

        return new DeviceInfo
        {
            IpAddress = ip,
            MacAddress = string.IsNullOrEmpty(mac) ? "—" : VendorService.NormalizeMac(mac),
            Hostname = hostname,
            FriendlyName = described?.FriendlyName ?? "",
            Model = described?.Model ?? "",
            ModelId = identity?.ModelId ?? "",
            Vendor = vendor,
            Status = "Online",
            IsLocalDevice = ip == network.IpAddress,
            // O gateway é, por definição, o router (seja qual for o fabricante: Sagemcom, ZTE, TP-Link…).
            DeviceType = ip == network.Gateway ? "Router" : described?.DeviceType ?? VendorService.GetDeviceType(vendor, hostname),
            LastSeen = DateTime.Now
        };
    }

    private static async Task<DeviceInfo> AnalyzeDeviceAsync(
        string ip, string mac, LocalNetworkInfo network, ScanOptions options,
        Vulnerabilities.VulnerabilityService? vulnerabilityService, Clues clues, CancellationToken ct)
    {
        var hostname = await ResolveHostnameAsync(ip);
        if (ip == network.Gateway && string.IsNullOrWhiteSpace(hostname))
            hostname = "router";

        var openPorts = "";
        var services = new List<ServiceInfo>();
        var vulnerabilities = new List<VulnerabilityInfo>();

        // O gateway (router) também é analisado: é o dispositivo mais exposto da rede.
        if (options.PortScan)
        {
            var ports = await ScanPortsAsync(ip, ct);
            openPorts = ports.Count > 0 ? string.Join(", ", ports) : "";

            if (options.ServiceDetection && ports.Count > 0)
                services = await ServiceDetectionService.DetectServicesAsync(ip, ports, ct);
        }

        // UPnP (SSDP, UDP 1900): o cabeçalho SERVER anuncia a pilha UPnP (ex.: libupnp 1.6.21 em routers).
        if (options.ServiceDetection && !string.IsNullOrWhiteSpace(clues.Ssdp?.Server))
            services.Add(ServiceDetectionService.FromBanner(1900, "UPnP (SSDP)", Vulnerabilities.BannerParser.SsdpPrefix + clues.Ssdp.Server));

        if (vulnerabilityService != null && services.Count > 0)
            vulnerabilities = await vulnerabilityService.CheckAsync(services, ct);

        var operatingSystem = "";
        var osConfidence = "";
        if (options.OSDetection)
        {
            var osResult = await OSFingerprintService.DetectOSAsync(ip, ct);
            operatingSystem = osResult.LikelyOS;
            osConfidence = osResult.Confidence;
        }

        var basic = BasicDevice(ip, mac, hostname, network, clues);
        return new DeviceInfo
        {
            IpAddress = basic.IpAddress,
            MacAddress = basic.MacAddress,
            Hostname = basic.Hostname,
            FriendlyName = basic.FriendlyName,
            Model = basic.Model,
            ModelId = basic.ModelId,
            Vendor = basic.Vendor,
            Status = basic.Status,
            IsLocalDevice = basic.IsLocalDevice,
            DeviceType = basic.DeviceType,
            LastSeen = basic.LastSeen,
            OpenPorts = openPorts,
            OperatingSystem = operatingSystem,
            OSConfidence = osConfidence,
            Services = services,
            Vulnerabilities = vulnerabilities
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
            // A resolução inversa no Windows pode esperar vários segundos por NetBIOS/LLMNR: limite de 2,5 s.
            var lookup = Dns.GetHostEntryAsync(ip);
            if (await Task.WhenAny(lookup, Task.Delay(2500)) != lookup)
            {
                // A resolução não se pode cancelar: observar o resultado tardio para não gerar erros "não observados".
                _ = lookup.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                return "";
            }
            var entry = await lookup;
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
            // Timeout por cancelamento (não por Task.WhenAny): a ligação é cancelada e observada, em vez de ficar
            // abandonada e falhar mais tarde sem ninguém a ler.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(300);
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Parse(ip), port, timeout.Token);
                if (client.Connected)
                    open.Add(port);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw; // cancelamento do scan pelo utilizador
            }
            catch
            {
                // fechada, filtrada ou sem resposta em 300 ms
            }
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
