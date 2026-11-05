using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using static Nodar.Core.Localization.Loc;

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

    /// <summary>Grupo para os filtros (computers, phones, tv…): ver <see cref="DeviceFilters"/>.</summary>
    public string Group => DeviceFilters.GroupOf(Device.DeviceType, IsGateway, Device.IsLocalDevice);

    public DeviceInfo Device { get; }
    public DeviceHistoryEntry? History { get; }
    /// <summary>Identidade no histórico (ver <see cref="DeviceTracker.Key(DeviceInfo)"/>).</summary>
    public string Key { get; }

    public string DisplayName =>
        !string.IsNullOrWhiteSpace(Device.FriendlyName) ? Device.FriendlyName :
        IsGateway && string.IsNullOrWhiteSpace(Device.Hostname) ? T("net.router") :
        !string.IsNullOrWhiteSpace(Device.Hostname) ? TrimDomain(Device.Hostname) :
        !Visuals.IsUnknownVendor(Device.Vendor) ? Visuals.VendorLabel(Device.Vendor) :
        Device.IpAddress;

    public string IpAddress => Device.IpAddress;
    public string MacAddress => string.IsNullOrWhiteSpace(Device.MacAddress) ? "—" : Device.MacAddress;
    public string Vendor => Visuals.VendorLabel(Device.Vendor);
    public string TypeLabel => IsGateway ? T("type.Router") : Device.IsLocalDevice ? T("type.thisComputer") : Visuals.TypeLabel(Device.DeviceType);
    public string Subtitle => $"{Device.IpAddress}  ·  {(!string.IsNullOrWhiteSpace(Device.Model) ? Device.Model : Visuals.IsUnknownVendor(Device.Vendor) ? TypeLabel : Vendor)}";
    public string Hostname => string.IsNullOrWhiteSpace(Device.Hostname) ? "—" : Device.Hostname;
    public string Model => string.IsNullOrWhiteSpace(Device.Model) ? "—"
        : !string.IsNullOrWhiteSpace(Device.ModelId) && Device.ModelId != Device.Model ? $"{Device.Model} ({Device.ModelId})"
        : Device.Model;
    public string OperatingSystem => string.IsNullOrWhiteSpace(Device.OperatingSystem)
        ? "—"
        : F("details.osConfidence", Device.OperatingSystem, Visuals.ConfidenceLabel(Device.OSConfidence));

    public Geometry Icon { get; }
    public IBrush IconTint { get; }
    public IBrush IconGlyph { get; }

    public bool IsGateway { get; }
    public bool IsLocal => Device.IsLocalDevice;
    public bool IsOnline { get; }
    public IBrush StatusBrush => IsOnline ? Visuals.OnlineBrush : Visuals.OfflineBrush;
    public string StatusText => IsOnline ? T("status.online") : F("status.offlineSince", Visuals.Relative(History?.LastLeftAt ?? History?.SeenAt));

    /// <summary>Apareceu pela primeira vez nas últimas 24 h (depois do primeiro scan de sempre).</summary>
    public bool IsNew { get; }
    public string FirstSeen => History?.FirstSeenAt is { } f ? f.ToString("g", Instance.Culture) : "—";
    public string LastSeen => IsOnline ? T("time.now") : Visuals.Relative(History?.SeenAt);

    [ObservableProperty]
    private bool _isWatched;

    // Portas e serviços
    public IReadOnlyList<ServiceItemViewModel> Services { get; }
    public bool HasServices => Services.Count > 0;
    public int OpenPortCount => string.IsNullOrWhiteSpace(Device.OpenPorts) ? 0 : Device.OpenPorts.Split(',').Length;
    public bool HasOpenPorts => OpenPortCount > 0;
    public string PortsText => Plural("badge.ports", OpenPortCount);

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
        ? F("badge.cve", Vulnerabilities.Count) + " · " + Plural("badge.exploited", KevCount)
        : F("badge.cve", Vulnerabilities.Count);
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
    public string Name => service.Service == "unknown" ? T("vendor.unknown") : service.Service;

    public string Product
    {
        get
        {
            var text = string.Join(" ", new[] { service.Product, service.Version }.Where(s => !string.IsNullOrWhiteSpace(s)));
            if (text.Equals(service.Service, StringComparison.OrdinalIgnoreCase))
                text = "";
            return text.Length == 0 ? T("service.unidentified") : text + (service.IsDistroPackage ? $" ({service.DistroName})" : "");
        }
    }

    public string CheckText => service.VulnerabilityCheck switch
    {
        VulnerabilityCheckStatus.Checked => T("check.checked"),
        VulnerabilityCheckStatus.CheckedWithStaleData => T("check.stale"),
        VulnerabilityCheckStatus.VersionUnknown => T("check.versionUnknown"),
        VulnerabilityCheckStatus.UnsupportedProduct => T("check.unsupported"),
        VulnerabilityCheckStatus.SourceUnavailable => T("check.unavailable"),
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
    public string Where => F("vuln.where", vuln.Product, vuln.DetectedVersion, vuln.Port);
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
    public string KevText => vuln.KnownRansomwareUse ? T("vuln.exploitedRansomware") : T("security.exploited");
    public bool MayBeBackported => vuln.MayBeBackported;
}

public sealed class HistoryEventViewModel(DeviceHistoryEvent e, string deviceName)
{
    public DateTime Timestamp => e.Timestamp;
    public string DeviceName => deviceName;
    public bool IsArrival => e.EventType == DeviceHistoryEventType.Seen;
    public string Title => IsArrival ? T("event.joined") : T("event.left");
    public string TitleWithDevice => IsArrival ? F("event.deviceJoined", deviceName) : F("event.deviceLeft", deviceName);
    public string When => e.Timestamp.ToString(Instance.Language == "pt" ? "dd/MM HH:mm" : "MMM d, HH:mm", Instance.Culture);
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
    public string StatusText => IsOnline ? T("status.online") : T("status.offline");
    public string Since => F("watch.since", Model.AddedAt.ToString("d", Instance.Culture));

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
