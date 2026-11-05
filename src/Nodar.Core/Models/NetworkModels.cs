namespace Nodar.Core.Models;

public sealed class LocalNetworkInfo
{
    public string InterfaceName { get; init; } = "";
    public string IpAddress { get; init; } = "";
    public string SubnetMask { get; init; } = "";
    public string Gateway { get; init; } = "";
    public string NetworkRange { get; init; } = "";
    public string Hostname { get; init; } = "";
    public string MacAddress { get; init; } = "";
}

public sealed class DeviceInfo
{
    public string IpAddress { get; init; } = "";
    public string MacAddress { get; init; } = "";
    public string Hostname { get; init; } = "";
    public string Vendor { get; init; } = "";
    public string Status { get; init; } = "Online";
    public string OpenPorts { get; init; } = "";
    public bool IsLocalDevice { get; init; }
    public string DeviceType { get; init; } = "Dispositivo";
    public DateTime LastSeen { get; init; } = DateTime.Now;
    
    // Advanced audit features
    public string OperatingSystem { get; init; } = "";
    public string OSConfidence { get; init; } = "";
    public List<ServiceInfo> Services { get; init; } = [];
    public List<VulnerabilityInfo> Vulnerabilities { get; init; } = [];

    public string DisplayName =>
        !string.IsNullOrWhiteSpace(Hostname) ? Hostname :
        !string.IsNullOrWhiteSpace(Vendor) && Vendor != "Desconhecido" ? Vendor :
        IpAddress;
}

public sealed class ServiceInfo
{
    public int Port { get; set; }
    public string Service { get; set; } = "";
    public string Version { get; set; } = "";
    public string Product { get; set; } = "";
    public string Banner { get; set; } = "";

    /// <summary>Chave interna do produto no <c>ProductCatalog</c> (vazio se não identificado).</summary>
    public string ProductKey { get; set; } = "";

    /// <summary>
    /// Verdadeiro quando o banner indica um pacote de distribuição (ex.: "Ubuntu", "Debian").
    /// Estas distribuições aplicam correções de segurança sem alterar o número de versão,
    /// por isso as correspondências por versão podem ser falsos positivos.
    /// </summary>
    public bool IsDistroPackage { get; set; }
    public string DistroName { get; set; } = "";

    public VulnerabilityCheckStatus VulnerabilityCheck { get; set; } = VulnerabilityCheckStatus.NotRequested;
}

public enum VulnerabilityCheckStatus
{
    /// <summary>A verificação de vulnerabilidades não foi pedida.</summary>
    NotRequested,
    /// <summary>Produto e versão verificados contra a NVD.</summary>
    Checked,
    /// <summary>Verificado com dados em cache desatualizados (sem ligação à NVD).</summary>
    CheckedWithStaleData,
    /// <summary>Não foi possível identificar o produto ou a versão a partir do banner.</summary>
    VersionUnknown,
    /// <summary>Produto identificado mas ainda não suportado pelo catálogo.</summary>
    UnsupportedProduct,
    /// <summary>A NVD não está acessível e não há cache.</summary>
    SourceUnavailable
}

public sealed class VulnerabilityInfo
{
    public string Service { get; set; } = "";
    public int Port { get; set; }
    public string Product { get; set; } = "";
    public string DetectedVersion { get; set; } = "";

    /// <summary>Critical, High, Medium, Low ou Unknown.</summary>
    public string Severity { get; set; } = "";
    public double? CvssScore { get; set; }
    public string CvssVersion { get; set; } = "";
    public string CVE { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime? Published { get; set; }

    /// <summary>Presente no catálogo CISA KEV (exploração ativa confirmada).</summary>
    public bool IsKnownExploited { get; set; }
    public bool KnownRansomwareUse { get; set; }

    /// <summary>Ver <see cref="ServiceInfo.IsDistroPackage"/>.</summary>
    public bool MayBeBackported { get; set; }

    public string Url => string.IsNullOrEmpty(CVE) ? "" : $"https://nvd.nist.gov/vuln/detail/{CVE}";
}

public sealed class ScanResult
{
    public LocalNetworkInfo? Network { get; init; }
    public List<DeviceInfo> Devices { get; init; } = [];
    public string ScanMethod { get; init; } = "";
    public TimeSpan Duration { get; init; }

    /// <summary>Resumo de como foi feita a verificação de vulnerabilidades (fonte, cache, falhas).</summary>
    public string? VulnerabilitySourceNote { get; init; }
    public string? Error { get; init; }
}

public sealed class ScanOptions
{
    public bool DeepScan { get; init; }
    public bool PortScan { get; init; }
    public bool OSDetection { get; init; }
    public bool ServiceDetection { get; init; }
    public bool VulnerabilityScan { get; init; }
    public bool AdvancedPortScan { get; init; }
    public IProgress<ScanProgress>? Progress { get; init; }
    public CancellationToken CancellationToken { get; init; }
    public Services.TimingTemplates.TimingLevel TimingLevel { get; init; } = Services.TimingTemplates.TimingLevel.Normal;
}

public sealed class ScanProgress
{
    public int Percent { get; init; }
    public string Message { get; init; } = "";
    public int DevicesFound { get; init; }
}

public enum DeviceHistoryEventType
{
    Seen,
    Left
}

public sealed class DeviceHistoryEvent
{
    public DeviceHistoryEventType EventType { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string Status { get; set; } = "Online";
}

public sealed class DeviceHistoryEntry
{
    public string IpAddress { get; set; } = "";
    public string MacAddress { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string Vendor { get; set; } = "";
    public string DeviceType { get; set; } = "Dispositivo";
    public string Status { get; set; } = "Online";
    public DateTime SeenAt { get; set; } = DateTime.Now;
    public DateTime? LastLeftAt { get; set; }
    public List<DeviceHistoryEvent> Events { get; set; } = [];
}

public sealed class WatchedDevice
{
    public string IpAddress { get; set; } = "";
    public string MacAddress { get; set; } = "";
    public string Name { get; set; } = "";
    public bool NotifyOnEnter { get; set; } = true;
    public bool NotifyOnLeave { get; set; } = true;
    public DateTime AddedAt { get; set; } = DateTime.Now;
}
