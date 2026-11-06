using System.Collections.ObjectModel;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using Nodar.Core.Services;
using static Nodar.Core.Localization.Loc;

namespace Nodar.App.ViewModels;

/// <summary>O que um scan trouxe de novo em matéria de exposição (para avisar o utilizador).</summary>
/// <param name="NewMappings">Portas que o router abriu para a internet desde o scan anterior.</param>
/// <param name="NewGatewayAlert">Alerta do MAC do router que ainda não tinha sido anunciado nesta sessão.</param>
public sealed record ExposureChanges(IReadOnlyList<PortMapping> NewMappings, GatewayAlert? NewGatewayAlert)
{
    public static ExposureChanges None { get; } = new([], null);
}

/// <summary>
/// O que a rede expõe: as portas que o router abriu para a internet (UPnP), o alerta de o MAC do router ter
/// mudado e, a pedido do utilizador, o que a internet vê do endereço público (Shodan).
/// </summary>
public sealed partial class ExposureViewModel : ObservableObject
{
    private readonly GatewayGuard _guard;
    private readonly PortMappingTracker _mappings;
    private readonly Func<string?, CancellationToken, Task<InternetExposure>> _lookup;
    private readonly HashSet<string> _announced = [];
    private UpnpReport? _upnp;
    private GatewayAlert? _alert;
    private InternetExposure? _internet;
    private IReadOnlyList<DeviceItemViewModel> _devices = [];

    /// <summary>O utilizador confirmou o MAC do router.</summary>
    public event Action? GatewayTrusted;

    /// <param name="lookup">Consulta à internet (por omissão o Shodan; a demonstração e os testes trocam-na).</param>
    public ExposureViewModel(GatewayGuard guard, PortMappingTracker mappings,
        Func<string?, CancellationToken, Task<InternetExposure>>? lookup = null)
    {
        _guard = guard;
        _mappings = mappings;
        _lookup = lookup ?? ((ip, ct) => InternetExposureService.CheckAsync(ip, ct));
    }

    // ================================================================ Um scan terminou

    /// <summary>Regista o resultado de um scan nos históricos (uma vez por scan) e devolve o que é novo.</summary>
    public ExposureChanges ApplyScan(ScanResult result)
    {
        _upnp = result.Upnp;
        var added = _upnp == null ? [] : _mappings.Apply(_upnp);

        _alert = null;
        GatewayAlert? fresh = null;
        if (result.Network is { Gateway: { Length: > 0 } gateway })
        {
            _alert = _guard.Evaluate(gateway, result.Devices);
            if (_alert != null && _announced.Add(_alert.Key))
                fresh = _alert; // anuncia-se uma vez por sessão; o cartão fica até o utilizador decidir
        }
        return new ExposureChanges(added, fresh);
    }

    /// <summary>Refaz o que se vê (também quando muda o idioma ou a lista de dispositivos).</summary>
    public void Update(IReadOnlyList<DeviceItemViewModel> devices)
    {
        _devices = devices;
        RenderUpnp();
        RenderGateway();
        RenderInternet();
    }

    private string NameOf(string ip) =>
        _devices.FirstOrDefault(d => d.IsOnline && d.IpAddress == ip)?.DisplayName is { } name && name != ip
            ? $"{name} ({ip})"
            : ip;

    // ================================================================ Portas abertas pelo router (UPnP)

    public ObservableCollection<PortMappingItemViewModel> PortMappings { get; } = [];

    [ObservableProperty] private bool _showUpnp;
    [ObservableProperty] private bool _hasPortMappings;
    [ObservableProperty] private string _upnpHeadline = "";
    [ObservableProperty] private string _upnpDetail = "";
    [ObservableProperty] private string _upnpExternal = "";
    [ObservableProperty] private bool _hasUpnpExternal;
    [ObservableProperty] private IBrush _upnpBrush = Visuals.SeverityBrush("None");
    [ObservableProperty] private IBrush _upnpSoftBrush = Visuals.SeveritySoftBrush("None");

    /// <summary>Há algo que o utilizador deve ver já (portas sensíveis abertas ou o router a ser imitado).</summary>
    [ObservableProperty] private bool _needsAttention;

    private void RenderUpnp()
    {
        PortMappings.Clear();
        ShowUpnp = _upnp != null;
        if (_upnp == null)
        {
            HasPortMappings = false;
            HasUpnpExternal = false;
            RefreshAttention();
            return;
        }

        var online = _devices.Where(d => d.IsOnline).GroupBy(d => d.IpAddress).ToDictionary(g => g.Key, g => g.First());
        foreach (var mapping in _upnp.Mappings
                     .OrderByDescending(m => m.Enabled && ExposureAdvice.SensitiveService(m.InternalPort) != null)
                     .ThenByDescending(m => m.Enabled)
                     .ThenBy(m => m.ExternalPort))
        {
            online.TryGetValue(mapping.InternalClient, out var device);
            PortMappings.Add(new PortMappingItemViewModel(mapping, device?.DisplayName, _mappings.FirstSeen(mapping)));
        }
        HasPortMappings = PortMappings.Count > 0;

        var active = _upnp.Mappings.Count(m => m.Enabled);
        var sensitive = PortMappings.Count(m => m.IsSensitive);
        var (headline, detail, severity) = _upnp.Status switch
        {
            UpnpStatus.Ok when active == 0 => (T("upnp.none"), T("upnp.none.hint"), "Low"),
            UpnpStatus.Ok => (Plural("upnp.count", active),
                sensitive > 0 ? Plural("upnp.sensitive", sensitive) : T("upnp.count.hint"),
                sensitive > 0 ? "Critical" : "Medium"),
            UpnpStatus.NotFound => (T("upnp.notFound"), T("upnp.notFound.hint"), "Low"),
            UpnpStatus.ListingRefused => (T("upnp.refused"), T("upnp.refused.hint"), "None"),
            _ => (T("upnp.failed"), T("upnp.failed.hint"), "None")
        };
        UpnpHeadline = headline;
        UpnpDetail = _upnp.Truncated ? detail + " " + T("upnp.truncated") : detail;
        UpnpBrush = Visuals.SeverityBrush(severity);
        UpnpSoftBrush = Visuals.SeveritySoftBrush(severity);
        HasUpnpExternal = _upnp.ExternalIp != null;
        UpnpExternal = _upnp.ExternalIp == null ? "" : F("upnp.external", _upnp.ExternalIp);
        RefreshAttention(sensitive);
    }

    private void RefreshAttention(int sensitiveMappings = 0) =>
        NeedsAttention = _alert != null || sensitiveMappings > 0;

    // ================================================================ O MAC do router mudou

    [ObservableProperty] private bool _hasGatewayAlert;
    [ObservableProperty] private string _gatewayAlertTitle = "";
    [ObservableProperty] private string _gatewayAlertText = "";
    [ObservableProperty] private IBrush _gatewayAlertBrush = Visuals.SeverityBrush("Medium");
    [ObservableProperty] private IBrush _gatewayAlertSoftBrush = Visuals.SeveritySoftBrush("Medium");

    private void RenderGateway()
    {
        HasGatewayAlert = _alert != null;
        if (_alert is not { } alert)
            return;

        var severity = alert.IsStrong ? "Critical" : "Medium";
        GatewayAlertBrush = Visuals.SeverityBrush(severity);
        GatewayAlertSoftBrush = Visuals.SeveritySoftBrush(severity);
        GatewayAlertTitle = alert.IsStrong ? T("gateway.strong.title") : T("gateway.weak.title");
        GatewayAlertText = alert.IsStrong
            ? F("gateway.strong.text", alert.GatewayIp, alert.NewMac, NameOf(alert.OtherDeviceIp!), alert.KnownMac)
            : F("gateway.weak.text", alert.GatewayIp, alert.KnownMac, alert.NewMac);
    }

    /// <summary>O utilizador confirma que o MAC atual é mesmo do router (trocou de router ou está noutra rede).</summary>
    [RelayCommand]
    private void TrustGateway()
    {
        if (_alert is not { } alert)
            return;
        _guard.Trust(alert.GatewayIp, alert.NewMac);
        _announced.Remove(alert.Key);
        _alert = null;
        RenderGateway();
        RefreshAttention(PortMappings.Count(m => m.IsSensitive));
        GatewayTrusted?.Invoke();
    }

    // ================================================================ O que a internet vê (Shodan)

    public ObservableCollection<InternetPortItemViewModel> InternetPorts { get; } = [];
    public ObservableCollection<CveLinkItemViewModel> InternetVulns { get; } = [];

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckInternetCommand))]
    [NotifyPropertyChangedFor(nameof(InternetButtonText))]
    private bool _isCheckingInternet;

    [ObservableProperty] private bool _hasInternetResult;
    [ObservableProperty] private bool _hasInternetPorts;
    [ObservableProperty] private bool _hasInternetVulns;
    [ObservableProperty] private string _internetHeadline = "";
    [ObservableProperty] private string _internetDetail = "";
    [ObservableProperty] private string _internetChecked = "";
    [ObservableProperty] private IBrush _internetBrush = Visuals.SeverityBrush("None");
    [ObservableProperty] private IBrush _internetSoftBrush = Visuals.SeveritySoftBrush("None");

    public string InternetButtonText => IsCheckingInternet ? T("internet.checking")
        : _internet == null ? T("internet.check") : T("internet.recheck");

    /// <summary>
    /// Pergunta ao Shodan o que vê do endereço público. Só corre quando o utilizador carrega no botão: é a única
    /// coisa que o Nodar envia para fora do computador sobre a rede.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanCheckInternet))]
    private async Task CheckInternetAsync()
    {
        IsCheckingInternet = true;
        try
        {
            _internet = await _lookup(_upnp?.ExternalIp, CancellationToken.None);
        }
        finally
        {
            IsCheckingInternet = false;
        }
        RenderInternet();
    }

    private bool CanCheckInternet() => !IsCheckingInternet;

    private void RenderInternet()
    {
        InternetPorts.Clear();
        InternetVulns.Clear();
        HasInternetResult = _internet != null;
        OnPropertyChanged(nameof(InternetButtonText));
        if (_internet is not { } seen)
        {
            HasInternetPorts = HasInternetVulns = false;
            return;
        }

        var viaUpnp = _upnp?.Mappings.Where(m => m.OpenToWholeInternet).Select(m => m.ExternalPort).ToHashSet() ?? [];
        foreach (var port in seen.Ports)
            InternetPorts.Add(new InternetPortItemViewModel(port, viaUpnp.Contains(port)));
        foreach (var cve in seen.Vulns)
            InternetVulns.Add(new CveLinkItemViewModel(cve));
        HasInternetPorts = InternetPorts.Count > 0;
        HasInternetVulns = InternetVulns.Count > 0;

        var sensitive = InternetPorts.Any(p => p.IsSensitive);
        var (headline, detail, severity) = seen.Status switch
        {
            InternetCheckStatus.Ok => (Plural("internet.headline.ports", seen.Ports.Count, seen.Ip),
                seen.Vulns.Count > 0 ? Plural("internet.vulns", seen.Vulns.Count) : T("internet.ports.hint"),
                sensitive ? "Critical" : seen.Vulns.Count > 0 ? "High" : "Medium"),
            InternetCheckStatus.NothingSeen => (F("internet.nothing", seen.Ip), T("internet.nothing.hint"), "Low"),
            InternetCheckStatus.NotPublic => (F("internet.notPublic", seen.Ip), T("internet.notPublic.hint"), "Low"),
            _ => (T("internet.failed"), T("internet.failed.hint"), "None")
        };
        InternetHeadline = headline;
        InternetDetail = detail;
        InternetBrush = Visuals.SeverityBrush(severity);
        InternetSoftBrush = Visuals.SeveritySoftBrush(severity);
        InternetChecked = F("internet.checked", Visuals.Relative(seen.CheckedAt));
    }
}

/// <summary>Uma porta que o router abriu para a internet, ligada ao dispositivo a que se destina.</summary>
public sealed class PortMappingItemViewModel
{
    private readonly PortMapping _mapping;
    private readonly string? _deviceName;
    private readonly DateTime? _since;
    private readonly string? _sensitiveService;

    public PortMappingItemViewModel(PortMapping mapping, string? deviceName, DateTime? since)
    {
        _mapping = mapping;
        _deviceName = deviceName;
        _since = since;
        _sensitiveService = mapping.Enabled ? ExposureAdvice.SensitiveService(mapping.InternalPort) : null;
    }

    public PortMapping Model => _mapping;

    /// <summary>"TCP 554"</summary>
    public string External => $"{_mapping.Protocol} {_mapping.ExternalPort}";

    /// <summary>Quem recebe: o nome do dispositivo (se for conhecido) e o endereço e porta de destino.</summary>
    public string Target => string.IsNullOrWhiteSpace(_deviceName) || _deviceName == _mapping.InternalClient
        ? $"{_mapping.InternalClient}:{_mapping.InternalPort}"
        : $"{_deviceName} · {_mapping.InternalClient}:{_mapping.InternalPort}";

    /// <summary>O que o router diz que é (a aplicação que pediu) ou, sem isso, o nome da porta.</summary>
    public string Purpose => !string.IsNullOrWhiteSpace(_mapping.Description)
        ? _mapping.Description
        : ExposureAdvice.PortName(_mapping.InternalPort) ?? "";

    public bool HasPurpose => Purpose.Length > 0;

    public bool IsDisabled => !_mapping.Enabled;
    public bool IsSensitive => _sensitiveService != null;
    public string RiskText => _sensitiveService == null ? "" : F("upnp.risk", _sensitiveService);

    public string Scope => !_mapping.Enabled ? T("upnp.disabled")
        : _mapping.OpenToWholeInternet ? T("upnp.scope.all")
        : F("upnp.scope.one", _mapping.RemoteHost);

    /// <summary>"Vista pela 1.ª vez há 2 dias", e se tem prazo, que é temporária (a aplicação que a pediu renova-a).</summary>
    public string Since
    {
        get
        {
            var seen = _since == null ? "" : F("upnp.firstSeen", Visuals.Relative(_since));
            if (_mapping.LeaseSeconds <= 0)
                return seen;
            return seen.Length == 0 ? T("upnp.temporary") : $"{seen} · {T("upnp.temporary")}";
        }
    }

    public string Severity => IsDisabled ? "None" : IsSensitive ? "Critical" : "Medium";
    public IBrush Brush => Visuals.SeverityBrush(Severity);
    public IBrush SoftBrush => Visuals.SeveritySoftBrush(Severity);
}

/// <summary>Uma porta que o Shodan viu aberta no endereço público.</summary>
public sealed class InternetPortItemViewModel(int port, bool viaUpnp)
{
    public int Port => port;
    public string Name => ExposureAdvice.PortName(port) is { } name ? $"{port} · {name}" : port.ToString();
    public bool IsSensitive => ExposureAdvice.SensitiveService(port) != null;
    public bool ViaUpnp => viaUpnp;

    /// <summary>De onde vem a porta aberta: se o router a abriu por UPnP, sabe-se; se não, é redirecionamento manual ou gestão do router.</summary>
    public string Origin => viaUpnp ? T("internet.port.upnp") : T("internet.port.other");

    public IBrush Brush => Visuals.SeverityBrush(IsSensitive ? "Critical" : "Medium");
    public IBrush SoftBrush => Visuals.SeveritySoftBrush(IsSensitive ? "Critical" : "Medium");
}

public sealed class CveLinkItemViewModel(string cve)
{
    public string Cve => cve;
    public string Url => $"https://nvd.nist.gov/vuln/detail/{cve}";
}
