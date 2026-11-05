using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;

namespace Nodar.App.ViewModels;

public sealed partial class DeviceItemViewModel : ObservableObject
{
    public DeviceItemViewModel(DeviceInfo device, DeviceHistoryEntry? history, string key, bool isGateway, bool isOnline, bool isWatched, bool isNew = false)
    {
        IsNew = isNew;
        Key = key;
        Device = device;
        History = history;
        IsGateway = isGateway;
        IsOnline = isOnline;
        _isWatched = isWatched;

        var style = Visuals.ForType(device.DeviceType, isGateway, device.IsLocalDevice);
        Icon = Visuals.Icon(style.IconKey);
        IconTint = style.Tint;
        IconGlyph = style.Glyph;

        Services = device.Services.Select(s => new ServiceItemViewModel(s)).ToList();
        Vulnerabilities = device.Vulnerabilities
            .Select(v => new VulnerabilityItemViewModel(v, DisplayName, device.IpAddress))
            .ToList();
        Events = (history?.Events ?? [])
            .OrderByDescending(e => e.Timestamp)
            .Take(12)
            .Select(e => new HistoryEventViewModel(e, DisplayName))
            .ToList();
    }

    public DeviceInfo Device { get; }
    public DeviceHistoryEntry? History { get; }
    /// <summary>Identidade no histórico (ver <see cref="DeviceTracker.Key(DeviceInfo)"/>).</summary>
    public string Key { get; }

    public string DisplayName =>
        !string.IsNullOrWhiteSpace(Device.FriendlyName) ? Device.FriendlyName :
        IsGateway && string.IsNullOrWhiteSpace(Device.Hostname) ? "Router" :
        !string.IsNullOrWhiteSpace(Device.Hostname) ? TrimDomain(Device.Hostname) :
        !string.IsNullOrWhiteSpace(Device.Vendor) && Device.Vendor != "Desconhecido" ? Device.Vendor :
        Device.IpAddress;

    public string IpAddress => Device.IpAddress;
    public string MacAddress => string.IsNullOrWhiteSpace(Device.MacAddress) ? "—" : Device.MacAddress;
    public string Vendor => string.IsNullOrWhiteSpace(Device.Vendor) || Device.Vendor == "Router/Gateway" ? "Desconhecido" : Device.Vendor;
    public string TypeLabel => IsGateway ? "Router" : Device.IsLocalDevice ? "Este computador" : Device.DeviceType;
    public string Subtitle => $"{Device.IpAddress}  ·  {(!string.IsNullOrWhiteSpace(Device.Model) ? Device.Model : Vendor == "Desconhecido" ? TypeLabel : Vendor)}";
    public string Hostname => string.IsNullOrWhiteSpace(Device.Hostname) ? "—" : Device.Hostname;
    public string Model => string.IsNullOrWhiteSpace(Device.Model) ? "—"
        : !string.IsNullOrWhiteSpace(Device.ModelId) && Device.ModelId != Device.Model ? $"{Device.Model} ({Device.ModelId})"
        : Device.Model;
    public string OperatingSystem => string.IsNullOrWhiteSpace(Device.OperatingSystem)
        ? "—"
        : $"{Device.OperatingSystem} · confiança {Device.OSConfidence.ToLowerInvariant()}";

    public Geometry Icon { get; }
    public IBrush IconTint { get; }
    public IBrush IconGlyph { get; }

    public bool IsGateway { get; }
    public bool IsLocal => Device.IsLocalDevice;
    public bool IsOnline { get; }
    public IBrush StatusBrush => IsOnline ? Visuals.OnlineBrush : Visuals.OfflineBrush;
    public string StatusText => IsOnline ? "Online" : $"Offline · {Visuals.Relative(History?.LastLeftAt ?? History?.SeenAt)}";

    /// <summary>Apareceu pela primeira vez nas últimas 24 h (depois do primeiro scan de sempre).</summary>
    public bool IsNew { get; }
    public string FirstSeen => History?.FirstSeenAt is { } f ? f.ToString("dd/MM/yyyy HH:mm") : "—";
    public string LastSeen => IsOnline ? "agora" : Visuals.Relative(History?.SeenAt);

    [ObservableProperty]
    private bool _isWatched;

    // Portas e serviços
    public IReadOnlyList<ServiceItemViewModel> Services { get; }
    public bool HasServices => Services.Count > 0;
    public int OpenPortCount => string.IsNullOrWhiteSpace(Device.OpenPorts) ? 0 : Device.OpenPorts.Split(',').Length;
    public bool HasOpenPorts => OpenPortCount > 0;
    public string PortsText => OpenPortCount == 1 ? "1 porta" : $"{OpenPortCount} portas";

    // Vulnerabilidades
    public IReadOnlyList<VulnerabilityItemViewModel> Vulnerabilities { get; }
    public bool HasVulnerabilities => Vulnerabilities.Count > 0;
    public int KevCount => Vulnerabilities.Count(v => v.IsKnownExploited);
    public string TopSeverity => Device.Vulnerabilities
        .OrderByDescending(v => Visuals.SeverityRank(v.Severity))
        .Select(v => v.Severity)
        .FirstOrDefault() ?? "";
    public IBrush TopSeverityBrush => Visuals.SeverityBrush(TopSeverity);
    public IBrush TopSeveritySoftBrush => Visuals.SeveritySoftBrush(TopSeverity);
    public string VulnBadgeText => KevCount > 0
        ? $"{Vulnerabilities.Count} CVE · {KevCount} explorada{(KevCount > 1 ? "s" : "")}"
        : $"{Vulnerabilities.Count} CVE";
    public bool MayBeBackported => Device.Vulnerabilities.Any(v => v.MayBeBackported);

    public IReadOnlyList<HistoryEventViewModel> Events { get; }
    public bool HasEvents => Events.Count > 0;

    public bool Matches(string filter) =>
        string.IsNullOrWhiteSpace(filter) ||
        new[] { DisplayName, Device.IpAddress, Device.MacAddress, Device.Vendor, Device.Hostname, TypeLabel, Device.OperatingSystem, Device.Model, Device.FriendlyName }
            .Any(s => s?.Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase) == true);

    private static string TrimDomain(string host)
    {
        foreach (var suffix in new[] { ".home", ".lan", ".local", ".localdomain", ".fritz.box" })
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return host[..^suffix.Length];
        return host;
    }
}

public sealed class ServiceItemViewModel(ServiceInfo service)
{
    public string Port => service.Port.ToString();
    public string Name => service.Service == "unknown" ? "Desconhecido" : service.Service;

    public string Product
    {
        get
        {
            var text = string.Join(" ", new[] { service.Product, service.Version }.Where(s => !string.IsNullOrWhiteSpace(s)));
            if (text.Equals(service.Service, StringComparison.OrdinalIgnoreCase))
                text = "";
            return text.Length == 0 ? "Produto não identificado" : text + (service.IsDistroPackage ? $" ({service.DistroName})" : "");
        }
    }

    public string CheckText => service.VulnerabilityCheck switch
    {
        VulnerabilityCheckStatus.Checked => "Verificado na NVD",
        VulnerabilityCheckStatus.CheckedWithStaleData => "Verificado com cache (sem ligação)",
        VulnerabilityCheckStatus.VersionUnknown => "Versão não anunciada",
        VulnerabilityCheckStatus.UnsupportedProduct => "Produto não suportado",
        VulnerabilityCheckStatus.SourceUnavailable => "NVD inacessível",
        _ => ""
    };

    public bool HasCheck => CheckText.Length > 0;

    public IBrush CheckBrush => service.VulnerabilityCheck switch
    {
        VulnerabilityCheckStatus.Checked => Visuals.OnlineBrush,
        VulnerabilityCheckStatus.CheckedWithStaleData or VulnerabilityCheckStatus.SourceUnavailable => Visuals.SeverityBrush("Medium"),
        _ => Visuals.OfflineBrush
    };
}

public sealed class VulnerabilityItemViewModel(VulnerabilityInfo vuln, string deviceName, string deviceIp)
{
    public VulnerabilityInfo Model => vuln;
    public string Cve => vuln.CVE;
    public string Url => vuln.Url;
    public string DeviceName => deviceName;
    public string DeviceIp => deviceIp;
    public string Where => $"{vuln.Product} {vuln.DetectedVersion} · porta {vuln.Port}";
    public string WhereWithDevice => $"{deviceName} · {Where}";
    public string Description => vuln.Description;
    public string Severity => vuln.Severity;
    public string SeverityLabel => Visuals.SeverityLabel(vuln.Severity);
    public IBrush SeverityBrush => Visuals.SeverityBrush(vuln.Severity);
    public IBrush SeveritySoftBrush => Visuals.SeveritySoftBrush(vuln.Severity);
    public int SeverityRank => Visuals.SeverityRank(vuln.Severity);
    public string Score => vuln.CvssScore is { } s ? s.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) : "—";
    public double ScoreValue => vuln.CvssScore ?? -1;
    public bool IsKnownExploited => vuln.IsKnownExploited;
    public string KevText => vuln.KnownRansomwareUse ? "Explorada ativamente · ransomware" : "Explorada ativamente";
    public bool MayBeBackported => vuln.MayBeBackported;
}

public sealed class HistoryEventViewModel(DeviceHistoryEvent e, string deviceName)
{
    public DateTime Timestamp => e.Timestamp;
    public string DeviceName => deviceName;
    public bool IsArrival => e.EventType == DeviceHistoryEventType.Seen;
    public string Title => IsArrival ? "Entrou na rede" : "Saiu da rede";
    public string TitleWithDevice => IsArrival ? $"{deviceName} entrou na rede" : $"{deviceName} saiu da rede";
    public string When => e.Timestamp.ToString("dd/MM HH:mm");
    public string Relative => Visuals.Relative(e.Timestamp);
    public Geometry Icon => Visuals.Icon(IsArrival ? "Icon.ArrowIn" : "Icon.ArrowOut");
    public IBrush Brush => IsArrival ? Visuals.OnlineBrush : Visuals.OfflineBrush;
}

public sealed partial class WatchItemViewModel : ObservableObject
{
    private readonly Action _save;

    public WatchItemViewModel(WatchedDevice watched, bool isOnline, Action save)
    {
        Model = watched;
        IsOnline = isOnline;
        _save = save;
        _notifyOnEnter = watched.NotifyOnEnter;
        _notifyOnLeave = watched.NotifyOnLeave;
    }

    public WatchedDevice Model { get; }
    public string Name => Model.Name;
    public string Details => string.Join("  ·  ", new[] { Model.IpAddress, Model.MacAddress }.Where(s => !string.IsNullOrWhiteSpace(s) && s != "—"));
    public bool IsOnline { get; }
    public IBrush StatusBrush => IsOnline ? Visuals.OnlineBrush : Visuals.OfflineBrush;
    public string StatusText => IsOnline ? "Online" : "Offline";
    public string Since => $"A vigiar desde {Model.AddedAt:dd/MM/yyyy}";

    [ObservableProperty] private bool _notifyOnEnter;
    [ObservableProperty] private bool _notifyOnLeave;

    partial void OnNotifyOnEnterChanged(bool value)
    {
        Model.NotifyOnEnter = value;
        _save();
    }

    partial void OnNotifyOnLeaveChanged(bool value)
    {
        Model.NotifyOnLeave = value;
        _save();
    }
}

public enum ToastKind { Info, Success, Warning, Danger }

public sealed class ToastViewModel(string title, string message, ToastKind kind)
{
    public string Title => title;
    public string Message => message;
    public bool HasMessage => !string.IsNullOrWhiteSpace(message);

    public Geometry Icon => Visuals.Icon(kind switch
    {
        ToastKind.Success => "Icon.Check",
        ToastKind.Warning => "Icon.Alert",
        ToastKind.Danger => "Icon.Alert",
        _ => "Icon.Sparkle"
    });

    public IBrush Brush => kind switch
    {
        ToastKind.Success => Visuals.OnlineBrush,
        ToastKind.Warning => Visuals.SeverityBrush("Medium"),
        ToastKind.Danger => Visuals.SeverityBrush("Critical"),
        _ => new SolidColorBrush(Color.Parse("#A79CFF"))
    };
}
