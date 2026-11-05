using Nodar.Core.Models;
using Nodar.Core.Services.Vulnerabilities;

namespace Nodar.App.Services;

/// <summary>
/// Rede fictícia para o modo de demonstração (<c>Nodar.exe --demo</c>): serve para ver a interface com
/// vulnerabilidades e para capturas de ecrã. Os dispositivos são inventados, mas os serviços são verificados
/// contra a NVD real, por isso os CVEs mostrados são verdadeiros para essas versões.
/// </summary>
public static class DemoData
{
    public static bool IsEnabled { get; } =
        Environment.GetCommandLineArgs().Any(a => a.Equals("--demo", StringComparison.OrdinalIgnoreCase));

    public static string DataDirectory { get; } = PrepareDataDirectory();

    /// <summary>Pasta temporária, limpa em cada arranque: a demonstração nunca toca no histórico real.</summary>
    private static string PrepareDataDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nodar-demo");
        if (IsEnabled)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { }
        }
        return dir;
    }

    public static LocalNetworkInfo Network { get; } = new()
    {
        InterfaceName = "Wi-Fi",
        IpAddress = "192.168.1.23",
        SubnetMask = "255.255.255.0",
        Gateway = "192.168.1.1",
        NetworkRange = "192.168.1.0/24",
        Hostname = "macbook-ana"
    };

    public static async Task<ScanResult> BuildAsync(IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        progress?.Report(new ScanProgress { Percent = 20, Message = "Modo demonstração: a preparar rede fictícia…" });

        static ServiceInfo Svc(int port, string service, string key = "", string product = "", string version = "", string distro = "") => new()
        {
            Port = port, Service = service, ProductKey = key, Product = product, Version = version,
            IsDistroPackage = distro.Length > 0, DistroName = distro
        };

        var specs = new (DeviceInfo Device, List<ServiceInfo> Services)[]
        {
            (new DeviceInfo { IpAddress = "192.168.1.1", MacAddress = "D0:CF:0E:00:00:01", Hostname = "router", Vendor = "TP-Link", DeviceType = "Router", OpenPorts = "53, 80, 443, 49152" },
             [Svc(53, "DNS", "dnsmasq", "dnsmasq", "2.78"), Svc(80, "HTTP", "lighttpd", "lighttpd", "1.4.45"), Svc(49152, "UPnP", "miniupnpd", "MiniUPnPd", "1.9")]),
            (new DeviceInfo { IpAddress = "192.168.1.23", MacAddress = "3C:22:FB:10:4A:01", Hostname = "macbook-ana", Vendor = "Apple", DeviceType = "Computador", IsLocalDevice = true, OpenPorts = "" }, []),
            (new DeviceInfo { IpAddress = "192.168.1.40", MacAddress = "DC:A6:32:7B:00:12", Hostname = "homelab", Vendor = "Raspberry Pi", DeviceType = "Servidor", OpenPorts = "22, 80, 6379" },
             [Svc(22, "SSH", "openssh", "OpenSSH", "8.9p1", "Ubuntu"), Svc(80, "HTTP", "nginx", "nginx", "1.18.0", "Ubuntu"), Svc(6379, "Redis", "redis", "Redis", "6.0.16")]),
            (new DeviceInfo { IpAddress = "192.168.1.52", MacAddress = "00:11:32:AB:CD:EF", Hostname = "nas", Vendor = "Synology", DeviceType = "Servidor", OpenPorts = "21, 443" },
             [Svc(21, "FTP", "proftpd", "ProFTPD", "1.3.5"), Svc(443, "HTTPS", "nginx", "nginx", "1.20.1")]),
            (new DeviceInfo { IpAddress = "192.168.1.61", MacAddress = "F4:F5:D8:00:11:22", Hostname = "GoogleTV-sala", Vendor = "Google", DeviceType = "TV", OpenPorts = "8008" }, []),
            (new DeviceInfo { IpAddress = "192.168.1.77", MacAddress = "64:EB:8C:33:44:55", Hostname = "EPSON-escritorio", Vendor = "Epson", DeviceType = "Impressora", OpenPorts = "80, 631" },
             [Svc(80, "HTTP")]),
            (new DeviceInfo { IpAddress = "192.168.1.88", MacAddress = "A4:83:E7:66:77:88", Hostname = "iPhone-Joao", Vendor = "Apple", DeviceType = "Apple", OpenPorts = "" }, []),
            (new DeviceInfo { IpAddress = "192.168.1.95", MacAddress = "7C:BB:8A:99:00:11", Hostname = "PS5", Vendor = "Sony", DeviceType = "Consola", OpenPorts = "" }, []),
        };

        progress?.Report(new ScanProgress { Percent = 50, Message = "Modo demonstração: a verificar serviços na NVD…" });
        var vulnerabilityService = new VulnerabilityService();
        var devices = new List<DeviceInfo>();
        foreach (var (device, services) in specs)
        {
            ct.ThrowIfCancellationRequested();
            var vulns = services.Count > 0 ? await vulnerabilityService.CheckAsync(services, ct) : [];
            devices.Add(new DeviceInfo
            {
                IpAddress = device.IpAddress, MacAddress = device.MacAddress, Hostname = device.Hostname,
                Vendor = device.Vendor, DeviceType = device.DeviceType, IsLocalDevice = device.IsLocalDevice,
                OpenPorts = device.OpenPorts, Services = services, Vulnerabilities = vulns
            });
        }

        progress?.Report(new ScanProgress { Percent = 100, Message = "Concluído" });
        return new ScanResult
        {
            Network = Network,
            Devices = devices,
            ScanMethod = "Demonstração",
            VulnerabilitySourceNote = vulnerabilityService.BuildSourceNote()
        };
    }
}
