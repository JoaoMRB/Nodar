using System.Collections.ObjectModel;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using Nodar.Core.Models;
using Nodar.Core.Services;
using static Nodar.Core.Localization.Loc;

namespace Nodar.App.ViewModels;

/// <summary>Vista de Segurança: vulnerabilidades potenciais de todos os dispositivos online.</summary>
public sealed partial class SecurityViewModel : ObservableObject
{
    private ScanResult? _result;
    private int _vulnerableDeviceCount;

    public ObservableCollection<VulnerabilityItemViewModel> AllVulnerabilities { get; } = [];

    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumLowCount;
    [ObservableProperty] private bool _hasVulnerabilityData;

    /// <summary>Algum serviço foi mesmo verificado (a verificação estava ligada no último scan).</summary>
    public bool IsChecked => _result?.Devices.SelectMany(d => d.Services)
        .Any(s => s.VulnerabilityCheck != VulnerabilityCheckStatus.NotRequested) == true;

    public bool ShowNotChecked => _result != null && !IsChecked;
    public bool ShowAllClear => IsChecked && AllVulnerabilities.Count == 0;

    public string Subtitle => _result == null
        ? T("security.subtitle.waiting")
        : !IsChecked
        ? T("security.subtitle.off")
        : AllVulnerabilities.Count == 0
            ? T("security.allClear.hint")
            : F("security.subtitle.count", AllVulnerabilities.Count, Plural("security.subtitle.devices", _vulnerableDeviceCount));

    /// <param name="result">Último scan concluído (<c>null</c> enquanto ainda não houve nenhum).</param>
    /// <param name="devices">Os dispositivos da lista, online e offline.</param>
    /// <param name="vulnerableDeviceCount">Quantos dispositivos têm vulnerabilidades (para o subtítulo).</param>
    public void Update(ScanResult? result, IReadOnlyList<DeviceItemViewModel> devices, int vulnerableDeviceCount)
    {
        _result = result;
        _vulnerableDeviceCount = vulnerableDeviceCount;

        AllVulnerabilities.Clear();
        foreach (var v in devices.Where(d => d.IsOnline)
                     .SelectMany(d => d.Vulnerabilities)
                     .OrderByDescending(v => v.IsKnownExploited)
                     .ThenByDescending(v => v.SeverityRank)
                     .ThenByDescending(v => v.ScoreValue))
            AllVulnerabilities.Add(v);

        CriticalCount = AllVulnerabilities.Count(v => v.Severity == "Critical");
        HighCount = AllVulnerabilities.Count(v => v.Severity == "High");
        MediumLowCount = AllVulnerabilities.Count - CriticalCount - HighCount;
        HasVulnerabilityData = AllVulnerabilities.Count > 0;
        RenderTls(devices);
        Refresh();
    }

    // ================================================================ Certificados e TLS

    public ObservableCollection<TlsFindingItemViewModel> TlsFindings { get; } = [];

    /// <summary>Algum serviço TLS foi inspecionado no último scan.</summary>
    [ObservableProperty] private bool _showTls;
    [ObservableProperty] private bool _hasTlsFindings;
    [ObservableProperty] private string _tlsHeadline = "";
    [ObservableProperty] private string _tlsDetail = "";
    [ObservableProperty] private IBrush _tlsBrush = Visuals.SeverityBrush("Low");
    [ObservableProperty] private IBrush _tlsSoftBrush = Visuals.SeveritySoftBrush("Low");

    private void RenderTls(IReadOnlyList<DeviceItemViewModel> devices)
    {
        var online = devices.Where(d => d.IsOnline).ToList();
        var names = online.GroupBy(d => d.IpAddress).ToDictionary(g => g.Key, g => g.First().DisplayName);
        var now = DateTime.Now;
        var inspected = 0;
        var findings = new List<TlsFindingItemViewModel>();
        foreach (var device in online)
            foreach (var service in device.Device.Services.Where(s => s.Tls != null))
            {
                inspected++;
                findings.AddRange(TlsAnalyzer.Analyze(service.Tls!, service.Port, now)
                    .Select(f => new TlsFindingItemViewModel(f, device.DisplayName, device.IpAddress, names)));
            }

        TlsFindings.Clear();
        foreach (var finding in findings.OrderByDescending(f => f.SeverityRank).ThenBy(f => f.Where, StringComparer.Ordinal))
            TlsFindings.Add(finding);

        ShowTls = inspected > 0;
        HasTlsFindings = TlsFindings.Count > 0;
        TlsHeadline = HasTlsFindings ? Plural("tls.count", TlsFindings.Count) : T("tls.ok");
        TlsDetail = HasTlsFindings ? T("tls.hint") : Plural("tls.checked", inspected);

        var worst = HasTlsFindings ? TlsFindings[0].Severity : "Low";
        TlsBrush = Visuals.SeverityBrush(worst);
        TlsSoftBrush = Visuals.SeveritySoftBrush(worst);
    }

    /// <summary>Volta a ler os textos e os estados que dependem do resultado e do idioma.</summary>
    public void Refresh()
    {
        OnPropertyChanged(nameof(IsChecked));
        OnPropertyChanged(nameof(ShowNotChecked));
        OnPropertyChanged(nameof(ShowAllClear));
        OnPropertyChanged(nameof(Subtitle));
    }
}
