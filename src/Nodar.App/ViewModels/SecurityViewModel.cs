using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Nodar.Core.Models;
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
        Refresh();
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
