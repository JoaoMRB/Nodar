using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Nodar.App.Services;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using Nodar.Core.Services;
using Nodar.Core.Settings;

namespace Nodar.App.ViewModels;

public enum Page { Devices, Security, History, Watchlist }

public sealed partial class MainViewModel : ObservableObject
{
    private readonly IPlatformServices _platform;
    private readonly AppSettings _settings;
    private readonly DeviceTracker _tracker;
    private readonly DispatcherTimer _refreshTimer = new();
    private readonly DispatcherTimer _clockTimer = new() { Interval = TimeSpan.FromSeconds(30) };
    private CancellationTokenSource? _scanCts;
    private ScanResult? _lastResult;
    private DateTime? _lastScanAt;
    private List<DeviceItemViewModel> _allDevices = [];
    private IReadOnlyList<DeviceInfo>? _preliminary;
    private bool _loadingSettings;

    public MainViewModel(IPlatformServices platform)
    {
        _platform = platform;
        _settings = AppSettings.Load();
        _tracker = new DeviceTracker(DemoData.IsEnabled ? DemoData.DataDirectory : DeviceTracker.DefaultDataDirectory);
        _tracker.Load();

        _loadingSettings = true;
        DeepScan = _settings.DeepScan;
        PortScan = _settings.PortScan;
        OsDetection = _settings.OsDetection;
        ServiceDetection = _settings.ServiceDetection;
        VulnerabilityScan = _settings.VulnerabilityScan;
        AutoRefresh = _settings.AutoRefresh;
        ShowOffline = _settings.ShowOffline;
        SelectedInterval = IntervalOptions.FirstOrDefault(o => o.Seconds == _settings.RefreshIntervalSeconds) ?? IntervalOptions[1];
        _loadingSettings = false;

        IsAdmin = DemoData.IsEnabled || NetworkDiscoveryService.IsAdministrator();
        if (DemoData.IsEnabled)
            ShowNetwork(DemoData.Network);
        else
            LoadNetworkInfo();
        RebuildWatchlist();

        _refreshTimer.Tick += async (_, _) => { if (!IsScanning) await ScanAsync(); };
        _clockTimer.Tick += (_, _) => OnPropertyChanged(nameof(LastScanText));
        _clockTimer.Start();
        ConfigureRefreshTimer();
    }

    /// <summary>Chamado quando a janela abre: primeiro scan imediato.</summary>
    public async Task StartAsync() => await ScanAsync();

    // ================================================================ Rede

    [ObservableProperty] private string _localIp = "—";
    [ObservableProperty] private string _networkRange = "—";
    [ObservableProperty] private string _gateway = "—";
    [ObservableProperty] private string _interfaceName = "—";
    [ObservableProperty] private string _hostname = "—";
    [ObservableProperty] private bool _hasNetwork;
    public bool IsAdmin { get; }
    public bool ShowAdminHint => !IsAdmin;

    public bool IsDemo => DemoData.IsEnabled;

    private void LoadNetworkInfo() => ShowNetwork(NetworkDiscoveryService.GetLocalNetwork());

    private void ShowNetwork(LocalNetworkInfo? network)
    {
        HasNetwork = network != null;
        if (network == null)
            return;
        LocalIp = network.IpAddress;
        NetworkRange = network.NetworkRange;
        Gateway = network.Gateway;
        InterfaceName = network.InterfaceName;
        Hostname = network.Hostname;
    }

    // ================================================================ Navegação

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDevicesPage), nameof(IsSecurityPage), nameof(IsHistoryPage), nameof(IsWatchlistPage), nameof(PageTitle), nameof(PageSubtitle))]
    private Page _currentPage = Page.Devices;

    public bool IsDevicesPage => CurrentPage == Page.Devices;
    public bool IsSecurityPage => CurrentPage == Page.Security;
    public bool IsHistoryPage => CurrentPage == Page.History;
    public bool IsWatchlistPage => CurrentPage == Page.Watchlist;

    public string PageTitle => CurrentPage switch
    {
        Page.Security => "Segurança",
        Page.History => "Histórico",
        Page.Watchlist => "Monitorizados",
        _ => "Dispositivos"
    };

    public string PageSubtitle => CurrentPage switch
    {
        Page.Security => SecuritySubtitle,
        Page.History => $"{_tracker.History.Count} dispositivos conhecidos nesta rede",
        Page.Watchlist => WatchItems.Count == 0 ? "Recebe um aviso quando um dispositivo entra ou sai" : $"{WatchItems.Count} a vigiar",
        _ => DevicesSubtitle
    };

    [RelayCommand]
    private void Navigate(Page page) => CurrentPage = page;

    // ================================================================ Opções de scan

    [ObservableProperty] private bool _deepScan;
    [ObservableProperty] private bool _portScan;
    [ObservableProperty] private bool _osDetection;
    [ObservableProperty] private bool _serviceDetection;
    [ObservableProperty] private bool _vulnerabilityScan;
    [ObservableProperty] private bool _autoRefresh;
    [ObservableProperty] private bool _showOffline;
    [ObservableProperty] private IntervalOption? _selectedInterval;

    public IReadOnlyList<IntervalOption> IntervalOptions { get; } =
    [
        new(60, "1 minuto"),
        new(120, "2 minutos"),
        new(300, "5 minutos"),
        new(900, "15 minutos"),
    ];

    // Dependências: vulnerabilidades ⇒ serviços ⇒ portas.
    partial void OnVulnerabilityScanChanged(bool value)
    {
        if (value) { ServiceDetection = true; }
        SaveSettings();
    }

    partial void OnServiceDetectionChanged(bool value)
    {
        if (value) PortScan = true;
        else VulnerabilityScan = false;
        SaveSettings();
    }

    partial void OnPortScanChanged(bool value)
    {
        if (!value) ServiceDetection = false;
        SaveSettings();
    }

    partial void OnDeepScanChanged(bool value) => SaveSettings();
    partial void OnOsDetectionChanged(bool value) => SaveSettings();

    partial void OnAutoRefreshChanged(bool value)
    {
        SaveSettings();
        ConfigureRefreshTimer();
    }

    partial void OnSelectedIntervalChanged(IntervalOption? value)
    {
        SaveSettings();
        ConfigureRefreshTimer();
    }

    partial void OnShowOfflineChanged(bool value)
    {
        SaveSettings();
        RebuildDevices();
    }

    private void SaveSettings()
    {
        if (_loadingSettings)
            return;
        _settings.DeepScan = DeepScan;
        _settings.PortScan = PortScan;
        _settings.OsDetection = OsDetection;
        _settings.ServiceDetection = ServiceDetection;
        _settings.VulnerabilityScan = VulnerabilityScan;
        _settings.AutoRefresh = AutoRefresh;
        _settings.ShowOffline = ShowOffline;
        _settings.RefreshIntervalSeconds = SelectedInterval?.Seconds ?? 120;
        _settings.Save();
    }

    private void ConfigureRefreshTimer()
    {
        _refreshTimer.Stop();
        if (!AutoRefresh)
            return;
        _refreshTimer.Interval = TimeSpan.FromSeconds(SelectedInterval?.Seconds ?? 120);
        _refreshTimer.Start();
    }

    public string ScanModeSummary
    {
        get
        {
            var parts = new List<string> { DeepScan ? "Sub-rede completa" : "Rápido" };
            if (PortScan) parts.Add("portas");
            if (ServiceDetection) parts.Add("serviços");
            if (VulnerabilityScan) parts.Add("vulnerabilidades");
            if (OsDetection) parts.Add("SO");
            return string.Join(" · ", parts);
        }
    }

    // ================================================================ Scan

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isScanning;

    public bool IsIdle => !IsScanning;

    [ObservableProperty] private double _scanProgress;
    [ObservableProperty] private string _scanMessage = "";
    [ObservableProperty] private string? _vulnerabilitySourceNote;

    public string LastScanText => _lastScanAt == null ? "Ainda não analisado" : $"Última análise {Visuals.Relative(_lastScanAt)}";

    [RelayCommand]
    private async Task ScanAsync()
    {
        if (IsScanning)
            return;

        IsScanning = true;
        ScanProgress = 0;
        ScanMessage = "A preparar…";
        _scanCts = new CancellationTokenSource();
        OnPropertyChanged(nameof(ScanModeSummary));

        var progress = new Progress<ScanProgress>(p =>
        {
            ScanProgress = Math.Clamp(p.Percent, 0, 100);
            ScanMessage = p.Message;
        });

        // No primeiro scan, mostrar já os dispositivos encontrados (os detalhes chegam depois).
        var discovered = new Progress<IReadOnlyList<DeviceInfo>>(list =>
        {
            if (_lastResult != null)
                return;
            _preliminary = list;
            RebuildDevices();
        });

        try
        {
            var options = new ScanOptions
            {
                DeepScan = DeepScan,
                PortScan = PortScan,
                OSDetection = OsDetection,
                ServiceDetection = ServiceDetection,
                VulnerabilityScan = VulnerabilityScan,
                Progress = progress,
                DevicesDiscovered = discovered,
                CancellationToken = _scanCts.Token
            };

            var result = DemoData.IsEnabled
                ? await DemoData.BuildAsync(progress, _scanCts.Token)
                : await Task.Run(() => NetworkDiscoveryService.ScanAsync(options), _scanCts.Token);
            if (result.Error != null)
            {
                Toast("Não foi possível analisar", result.Error, ToastKind.Danger);
                return;
            }

            _lastResult = result;
            _lastScanAt = DateTime.Now;
            VulnerabilitySourceNote = result.VulnerabilitySourceNote;
            if (!DemoData.IsEnabled)
                LoadNetworkInfo();

            var update = _tracker.ApplyScan(result.Devices);
            RebuildDevices();
            RebuildWatchlist();
            AnnounceChanges(update, result);
        }
        catch (OperationCanceledException)
        {
            Toast("Análise cancelada", "", ToastKind.Info);
        }
        catch (Exception ex)
        {
            Toast("Erro na análise", ex.Message, ToastKind.Danger);
        }
        finally
        {
            IsScanning = false;
            ScanMessage = "";
            _scanCts?.Dispose();
            _scanCts = null;
            OnPropertyChanged(nameof(LastScanText));
        }
    }

    [RelayCommand]
    private void CancelScan() => _scanCts?.Cancel();

    private void AnnounceChanges(TrackerUpdate update, ScanResult result)
    {
        foreach (var device in update.NewDevices.Take(3))
            Toast("Novo dispositivo na rede", $"{FindItem(device)?.DisplayName ?? device.IpAddress} · {device.IpAddress}", ToastKind.Info);
        if (update.NewDevices.Count > 3)
            Toast($"+{update.NewDevices.Count - 3} dispositivos novos", "", ToastKind.Info);

        foreach (var e in update.WatchedArrived)
            Toast($"{e.Watched.Name} entrou na rede", e.IpAddress, ToastKind.Success);
        foreach (var e in update.WatchedLeft)
            Toast($"{e.Watched.Name} saiu da rede", e.IpAddress, ToastKind.Warning);

        if (update.NewDevices.Count > 0 || update.WatchedArrived.Count > 0 || update.WatchedLeft.Count > 0)
            _platform.FlashWindow();

        var sourceProblem = result.Devices.SelectMany(d => d.Services)
            .Any(s => s.VulnerabilityCheck is VulnerabilityCheckStatus.SourceUnavailable or VulnerabilityCheckStatus.CheckedWithStaleData);
        if (sourceProblem)
            Toast("NVD inacessível", "A verificação de vulnerabilidades está incompleta ou usa dados em cache.", ToastKind.Warning);
    }

    // ================================================================ Dispositivos

    public ObservableCollection<DeviceItemViewModel> Devices { get; } = [];

    [ObservableProperty] private string _searchText = "";
    partial void OnSearchTextChanged(string value) => ApplyFilter();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    private DeviceItemViewModel? _selectedDevice;

    public bool HasSelection => SelectedDevice != null;

    [ObservableProperty] private int _onlineCount;
    [ObservableProperty] private int _offlineCount;
    [ObservableProperty] private int _newCount;
    [ObservableProperty] private int _exposedServiceCount;
    [ObservableProperty] private int _vulnerableDeviceCount;
    [ObservableProperty] private int _vulnerabilityCount;
    [ObservableProperty] private int _kevCount;
    [ObservableProperty] private bool _hasDevices;
    [ObservableProperty] private bool _hasScanned;

    public bool ShowEmptyState => HasScanned && !HasDevices && Devices.Count == 0;
    public bool ShowFirstScan => !HasScanned;
    public bool NoSearchResults => HasDevices && Devices.Count == 0;

    public string DevicesSubtitle => !HasScanned
        ? "A procurar dispositivos na tua rede…"
        : $"{OnlineCount} online" + (OfflineCount > 0 && ShowOffline ? $" · {OfflineCount} offline" : "") + $" · {LastScanText.ToLowerInvariant()}";

    private void RebuildDevices()
    {
        var selectedKey = SelectedDevice?.Key;
        var gateway = Gateway;
        var items = new List<DeviceItemViewModel>();

        var source = _lastResult?.Devices ?? _preliminary;
        if (source != null)
        {
            var usedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var device in source)
            {
                var history = _tracker.GetHistory(device);
                // Na lista preliminar o histórico ainda não sabe de MACs partilhados (repetidores): garantir chaves únicas.
                var key = _tracker.Key(device);
                if (!usedKeys.Add(key))
                    usedKeys.Add(key = $"{key}@{device.IpAddress}");
                items.Add(new DeviceItemViewModel(device, history, key,
                    isGateway: device.IpAddress == gateway, isOnline: true,
                    isWatched: _tracker.FindWatched(device) != null,
                    isNew: _tracker.IsRecentlyNew(history, TimeSpan.FromHours(24))));
            }
        }

        var offline = _tracker.OfflineEntries().ToList();
        OfflineCount = offline.Count;
        if (ShowOffline)
        {
            var onlineKeys = items.Select(i => i.Key).ToHashSet();
            foreach (var entry in offline)
            {
                var device = FromHistory(entry);
                if (onlineKeys.Contains(_tracker.Key(device)))
                    continue;
                items.Add(new DeviceItemViewModel(device, entry, _tracker.Key(device), isGateway: false, isOnline: false,
                    isWatched: _tracker.FindWatched(device) != null));
            }
        }

        // Ordem: router, este PC, com vulnerabilidades, online por IP, offline por recência.
        _allDevices = items
            .OrderByDescending(d => d.IsOnline)
            .ThenByDescending(d => d.IsGateway)
            .ThenByDescending(d => d.IsLocal)
            .ThenBy(d => IpSortKey(d.IpAddress))
            .ToList();

        HasScanned = source != null;
        HasDevices = _allDevices.Count > 0;
        OnlineCount = _allDevices.Count(d => d.IsOnline);
        NewCount = _allDevices.Count(d => d.IsNew);
        ExposedServiceCount = _allDevices.Sum(d => d.Services.Count);
        VulnerableDeviceCount = _allDevices.Count(d => d.HasVulnerabilities);
        VulnerabilityCount = _allDevices.Sum(d => d.Vulnerabilities.Count);
        KevCount = _allDevices.Sum(d => d.KevCount);

        ApplyFilter();
        SelectedDevice = selectedKey == null ? null : Devices.FirstOrDefault(d => d.Key == selectedKey);
        RebuildSecurity();
        RebuildHistory();

        OnPropertyChanged(nameof(DevicesSubtitle));
        OnPropertyChanged(nameof(PageSubtitle));
        OnPropertyChanged(nameof(ShowFirstScan));
    }

    private void ApplyFilter()
    {
        var selected = SelectedDevice;
        Devices.Clear();
        foreach (var d in _allDevices.Where(d => d.Matches(SearchText)))
            Devices.Add(d);
        if (selected != null && Devices.Contains(selected))
            SelectedDevice = selected;
        OnPropertyChanged(nameof(ShowEmptyState));
        OnPropertyChanged(nameof(NoSearchResults));
    }

    [RelayCommand]
    private void CloseDetails() => SelectedDevice = null;

    [RelayCommand]
    private void ToggleWatch(DeviceItemViewModel? device)
    {
        device ??= SelectedDevice;
        if (device == null)
            return;

        var existing = _tracker.FindWatched(device.Device);
        if (existing != null)
        {
            _tracker.Unwatch(existing);
            device.IsWatched = false;
            Toast("Deixou de ser vigiado", device.DisplayName, ToastKind.Info);
        }
        else
        {
            _tracker.Watch(device.Device, device.DisplayName);
            device.IsWatched = true;
            Toast("A vigiar dispositivo", $"Vais receber um aviso quando {device.DisplayName} entrar ou sair.", ToastKind.Success);
        }
        RebuildWatchlist();
    }

    [RelayCommand]
    private async Task CopyAsync(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text == "—")
            return;
        await _platform.CopyToClipboardAsync(text);
        Toast("Copiado", text, ToastKind.Success);
    }

    [RelayCommand]
    private void OpenUrl(string? url)
    {
        if (!string.IsNullOrWhiteSpace(url))
            _platform.OpenUrl(url);
    }

    [RelayCommand]
    private void SelectDevice(DeviceItemViewModel? device)
    {
        if (device == null)
            return;
        CurrentPage = Page.Devices;
        SearchText = "";
        SelectedDevice = Devices.FirstOrDefault(d => d.Key == device.Key);
    }

    private DeviceItemViewModel? FindItem(DeviceInfo device) =>
        _allDevices.FirstOrDefault(d => d.Key == _tracker.Key(device));

    private static DeviceInfo FromHistory(DeviceHistoryEntry e) => new()
    {
        IpAddress = e.IpAddress,
        MacAddress = e.MacAddress,
        Hostname = e.Hostname,
        FriendlyName = e.FriendlyName,
        Model = e.Model,
        Vendor = e.Vendor,
        DeviceType = e.DeviceType,
        Status = DeviceTracker.Offline,
        LastSeen = e.SeenAt
    };

    private static long IpSortKey(string ip) =>
        System.Net.IPAddress.TryParse(ip, out var a) && a.GetAddressBytes() is { Length: 4 } b
            ? ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3]
            : long.MaxValue;

    // ================================================================ Segurança

    public ObservableCollection<VulnerabilityItemViewModel> AllVulnerabilities { get; } = [];
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumLowCount;
    [ObservableProperty] private bool _hasVulnerabilityData;

    public bool SecurityChecked => _lastResult?.Devices.SelectMany(d => d.Services)
        .Any(s => s.VulnerabilityCheck != VulnerabilityCheckStatus.NotRequested) == true;
    public bool ShowSecurityNotChecked => _lastResult != null && !SecurityChecked;
    public bool ShowSecurityAllClear => SecurityChecked && AllVulnerabilities.Count == 0;

    public string SecuritySubtitle => _lastResult == null
        ? "À espera da primeira análise…"
        : !SecurityChecked
        ? "Ativa a verificação de vulnerabilidades nas opções de análise"
        : AllVulnerabilities.Count == 0
            ? "Nenhuma vulnerabilidade conhecida nas versões detetadas"
            : $"{AllVulnerabilities.Count} vulnerabilidades potenciais em {VulnerableDeviceCount} dispositivo{(VulnerableDeviceCount == 1 ? "" : "s")}";

    private void RebuildSecurity()
    {
        AllVulnerabilities.Clear();
        foreach (var v in _allDevices.Where(d => d.IsOnline)
                     .SelectMany(d => d.Vulnerabilities)
                     .OrderByDescending(v => v.IsKnownExploited)
                     .ThenByDescending(v => v.SeverityRank)
                     .ThenByDescending(v => v.ScoreValue))
            AllVulnerabilities.Add(v);

        CriticalCount = AllVulnerabilities.Count(v => v.Severity == "Critical");
        HighCount = AllVulnerabilities.Count(v => v.Severity == "High");
        MediumLowCount = AllVulnerabilities.Count - CriticalCount - HighCount;
        HasVulnerabilityData = AllVulnerabilities.Count > 0;
        OnPropertyChanged(nameof(SecurityChecked));
        OnPropertyChanged(nameof(ShowSecurityNotChecked));
        OnPropertyChanged(nameof(ShowSecurityAllClear));
        OnPropertyChanged(nameof(SecuritySubtitle));
    }

    // ================================================================ Histórico

    public ObservableCollection<HistoryEventViewModel> RecentEvents { get; } = [];
    public ObservableCollection<DeviceItemViewModel> KnownDevices { get; } = [];
    [ObservableProperty] private bool _hasHistory;

    private void RebuildHistory()
    {
        RecentEvents.Clear();
        KnownDevices.Clear();

        var onlineKeys = _allDevices.Where(d => d.IsOnline)
            .GroupBy(d => d.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        foreach (var entry in _tracker.History.OrderByDescending(e => e.Status == DeviceTracker.Online).ThenByDescending(e => e.SeenAt))
        {
            var device = FromHistory(entry);
            var key = _tracker.Key(device);
            KnownDevices.Add(onlineKeys.TryGetValue(key, out var online)
                ? online
                : new DeviceItemViewModel(device, entry, key, false, entry.Status == DeviceTracker.Online, _tracker.FindWatched(device) != null));
        }

        foreach (var e in _tracker.History
                     .SelectMany(h => h.Events.Select(ev => (ev, name: NameFor(h))))
                     .OrderByDescending(x => x.ev.Timestamp)
                     .Take(40))
            RecentEvents.Add(new HistoryEventViewModel(e.ev, e.name));

        HasHistory = RecentEvents.Count > 0;
    }

    private static string NameFor(DeviceHistoryEntry h) =>
        !string.IsNullOrWhiteSpace(h.FriendlyName) ? h.FriendlyName :
        !string.IsNullOrWhiteSpace(h.Hostname) ? h.Hostname.Split('.')[0] :
        !string.IsNullOrWhiteSpace(h.Vendor) && h.Vendor != "Desconhecido" ? h.Vendor : h.IpAddress;

    // ================================================================ Monitorizados

    public ObservableCollection<WatchItemViewModel> WatchItems { get; } = [];
    [ObservableProperty] private bool _hasWatchItems;

    private void RebuildWatchlist()
    {
        WatchItems.Clear();
        var online = _lastResult?.Devices ?? [];
        foreach (var w in _tracker.Watchlist)
        {
            var isOnline = online.Any(d => _tracker.Key(d) == _tracker.Key(w.MacAddress, w.IpAddress));
            WatchItems.Add(new WatchItemViewModel(w, isOnline, _tracker.Save));
        }
        HasWatchItems = WatchItems.Count > 0;
        OnPropertyChanged(nameof(PageSubtitle));
    }

    [RelayCommand]
    private void RemoveWatch(WatchItemViewModel? item)
    {
        if (item == null)
            return;
        _tracker.Unwatch(item.Model);
        foreach (var d in _allDevices.Where(d => _tracker.FindWatched(d.Device) == null))
            d.IsWatched = false;
        RebuildWatchlist();
    }

    // ================================================================ Exportar

    [RelayCommand]
    private async Task ExportCsvAsync()
    {
        if (_lastResult == null)
            return;
        var path = await _platform.PickSaveFileAsync("Exportar dispositivos", $"nodar-dispositivos-{DateTime.Now:yyyyMMdd-HHmm}.csv", "csv", "CSV");
        if (path == null)
            return;
        try
        {
            ExportService.ExportToCsv(_lastResult.Devices, path);
            Toast("Exportado", Path.GetFileName(path), ToastKind.Success);
        }
        catch (Exception ex)
        {
            Toast("Não foi possível exportar", ex.Message, ToastKind.Danger);
        }
    }

    [RelayCommand]
    private async Task ExportReportAsync(string? format)
    {
        if (_lastResult == null)
            return;
        format ??= "html";
        var (ext, label) = format switch
        {
            "md" => ("md", "Markdown"),
            "json" => ("json", "JSON"),
            _ => ("html", "HTML")
        };

        var path = await _platform.PickSaveFileAsync("Guardar relatório", $"nodar-relatorio-{DateTime.Now:yyyyMMdd-HHmm}.{ext}", ext, label);
        if (path == null)
            return;

        try
        {
            var history = _tracker.History
                .GroupBy(h => h.IpAddress)
                .ToDictionary(g => g.Key, g => g.OrderByDescending(h => h.SeenAt).First());
            var options = new AuditReportService.AuditReportOptions();
            var report = ext switch
            {
                "md" => await AuditReportService.GenerateMarkdownReportAsync(_lastResult, history, options),
                "json" => await AuditReportService.GenerateJSONReportAsync(_lastResult, history, options),
                _ => await AuditReportService.GenerateHTMLReportAsync(_lastResult, history, options)
            };
            await File.WriteAllTextAsync(path, report);
            Toast("Relatório guardado", Path.GetFileName(path), ToastKind.Success);
        }
        catch (Exception ex)
        {
            Toast("Não foi possível gerar o relatório", ex.Message, ToastKind.Danger);
        }
    }

    // ================================================================ Notificações

    public ObservableCollection<ToastViewModel> Toasts { get; } = [];

    private void Toast(string title, string message, ToastKind kind)
    {
        var toast = new ToastViewModel(title, message, kind);
        Toasts.Add(toast);
        while (Toasts.Count > 4)
            Toasts.RemoveAt(0);

        DispatcherTimer.RunOnce(() => Toasts.Remove(toast), TimeSpan.FromSeconds(kind == ToastKind.Danger ? 9 : 5));
    }

    public void ReportUnexpectedError(Exception ex) =>
        Toast("Ocorreu um erro inesperado", $"{ex.Message} (registado em {CrashLog.Directory})", ToastKind.Danger);

    [RelayCommand]
    private void DismissToast(ToastViewModel? toast)
    {
        if (toast != null)
            Toasts.Remove(toast);
    }
}

public sealed record IntervalOption(int Seconds, string Label)
{
    public override string ToString() => Label;
}
