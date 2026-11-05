using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Nodar.App.Services;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using Nodar.Core.Services;
using Nodar.Core.Settings;
using Nodar.Core.Localization;
using static Nodar.Core.Localization.Loc;

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
        WindowsNotifications = _settings.WindowsNotifications;
        CloseToTray = _settings.CloseToTray;
        StartWithWindows = _settings.StartWithWindows;
        SelectedLanguage = LanguageOptions.FirstOrDefault(o => o.Code == _settings.Language) ?? LanguageOptions[0];
        StartupRegistration.Refresh(_settings.StartWithWindows);
        SelectedInterval = IntervalOptions.FirstOrDefault(o => o.Seconds == _settings.RefreshIntervalSeconds) ?? IntervalOptions[1];
        _loadingSettings = false;
        Instance.LanguageChanged += OnLanguageChanged;

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
    public async Task StartAsync()
    {
        if (_started)
            return;
        _started = true;
        await ScanAsync();
    }

    private bool _started;

    // ================================================================ Segundo plano e notificações do Windows

    [ObservableProperty] private bool _windowsNotifications;
    [ObservableProperty] private bool _closeToTray;
    [ObservableProperty] private bool _startWithWindows;

    /// <summary>Iniciar com o Windows só é possível a partir do executável publicado (Nodar.exe).</summary>
    public bool CanStartWithWindows => StartupRegistration.CurrentCommand() != null;

    partial void OnWindowsNotificationsChanged(bool value) => SaveSettings();

    // ================================================================ Idioma

    /// <summary>Opções fixas (nunca recriadas): ver <see cref="OnLanguageChanged"/>.</summary>
    public IReadOnlyList<LanguageOption> LanguageOptions { get; } = [new("auto"), new("pt"), new("en")];

    [ObservableProperty] private LanguageOption? _selectedLanguage;

    partial void OnSelectedLanguageChanged(LanguageOption? value)
    {
        // A caixa de seleção pode limpar a seleção por momentos: isso não é "escolher automático".
        if (value == null)
            return;
        Instance.Apply(value.Code);
        SaveSettings();
    }

    private bool _refreshPending;

    /// <summary>
    /// O idioma mudou. As listas das caixas de seleção nunca são recriadas (isso limpava a seleção e
    /// provocava um ciclo pt↔en que bloqueava a app): só os textos das opções são atualizados. O resto da
    /// interface é refeito depois de a caixa de seleção terminar o seu evento.
    /// </summary>
    private void OnLanguageChanged()
    {
        foreach (var option in LanguageOptions)
            option.Refresh();
        foreach (var option in IntervalOptions)
            option.Refresh();

        if (_refreshPending)
            return;
        _refreshPending = true;
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            _refreshPending = false;
            RebuildDevices();
            RebuildWatchlist();
            OnPropertyChanged(nameof(PageTitle));
            OnPropertyChanged(nameof(PageSubtitle));
            OnPropertyChanged(nameof(DevicesSubtitle));
            OnPropertyChanged(nameof(SecuritySubtitle));
            OnPropertyChanged(nameof(LastScanText));
            OnPropertyChanged(nameof(ScanModeSummary));
        }, Avalonia.Threading.DispatcherPriority.Background);
    }
    partial void OnCloseToTrayChanged(bool value) => SaveSettings();

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (_loadingSettings)
            return;
        if (!StartupRegistration.Set(value) && value)
        {
            Toast(T("toast.startup.failed"), T("toast.startup.failed.hint"), ToastKind.Warning);
            _loadingSettings = true;
            StartWithWindows = false;
            _loadingSettings = false;
        }
        SaveSettings();
    }

    /// <summary>Notificação do Windows, só quando o utilizador não está a ver a janela.</summary>
    private void NotifySystem(string title, string message)
    {
        if (WindowsNotifications && !_platform.IsUserLooking)
            _platform.NotifySystem(title, message);
    }

    /// <summary>A janela foi fechada mas a app continua na bandeja: explicar isso uma vez.</summary>
    public void OnHiddenToTray()
    {
        if (_settings.TrayHintShown)
            return;
        _settings.TrayHintShown = true;
        _settings.Save();
        _platform.NotifySystem(T("tray.hint.title"),
            AutoRefresh ? T("tray.hint.autoRefresh") : T("tray.hint.manual"));
    }

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
        Page.Security => T("nav.security"),
        Page.History => T("nav.history"),
        Page.Watchlist => T("nav.watchlist"),
        _ => T("nav.devices")
    };

    public string PageSubtitle => CurrentPage switch
    {
        Page.Security => SecuritySubtitle,
        Page.History => Plural("history.subtitle", _tracker.History.Count),
        Page.Watchlist => WatchItems.Count == 0 ? T("watch.subtitle.empty") : Plural("watch.subtitle", WatchItems.Count),
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

    public IReadOnlyList<IntervalOption> IntervalOptions { get; } = [new(60), new(120), new(300), new(900)];

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
        _settings.WindowsNotifications = WindowsNotifications;
        _settings.CloseToTray = CloseToTray;
        _settings.StartWithWindows = StartWithWindows;
        _settings.Language = SelectedLanguage?.Code ?? "auto";
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
            var parts = new List<string> { DeepScan ? T("mode.full") : T("mode.quick") };
            if (PortScan) parts.Add(T("mode.ports"));
            if (ServiceDetection) parts.Add(T("mode.services"));
            if (VulnerabilityScan) parts.Add(T("mode.vulns"));
            if (OsDetection) parts.Add(T("mode.os"));
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

    public string LastScanText => _lastScanAt == null ? T("scan.never") : F("scan.last", Visuals.Relative(_lastScanAt));

    [RelayCommand]
    private async Task ScanAsync()
    {
        if (IsScanning)
            return;

        IsScanning = true;
        ScanProgress = 0;
        ScanMessage = T("scan.preparing");
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
                Toast(T("toast.scan.failed"), result.Error, ToastKind.Danger);
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
            Toast(T("toast.scan.cancelled"), "", ToastKind.Info);
        }
        catch (Exception ex)
        {
            Toast(T("toast.scan.error"), ex.Message, ToastKind.Danger);
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
        string Describe(DeviceInfo d)
        {
            var item = FindItem(d);
            var name = item?.DisplayName ?? d.IpAddress;
            var detail = item != null && !Visuals.IsUnknownVendor(d.Vendor) ? item.Vendor : d.DeviceType == "Dispositivo" ? "" : Visuals.TypeLabel(d.DeviceType);
            return $"{name} · {d.IpAddress}" + (string.IsNullOrWhiteSpace(detail) ? "" : $" · {detail}");
        }

        // Dentro da app: um aviso por dispositivo (até 3).
        foreach (var device in update.NewDevices.Take(3))
            Toast(T("notify.newDevice"), Describe(device), ToastKind.Info);
        if (update.NewDevices.Count > 3)
            Toast(F("notify.moreNew", update.NewDevices.Count - 3), "", ToastKind.Info);

        // No Windows: uma só notificação para os novos (não inundar a central de notificações).
        if (update.NewDevices.Count == 1)
            NotifySystem(T("notify.newDevice"), Describe(update.NewDevices[0]));
        else if (update.NewDevices.Count > 1)
            NotifySystem(F("notify.newDevices", update.NewDevices.Count),
                string.Join("\n", update.NewDevices.Take(4).Select(Describe)) + (update.NewDevices.Count > 4 ? "\n…" : ""));

        foreach (var e in update.WatchedArrived)
        {
            Toast(F("event.deviceJoined", e.Watched.Name), e.IpAddress, ToastKind.Success);
            NotifySystem(F("event.deviceJoined", e.Watched.Name), $"{e.DeviceName} · {e.IpAddress}");
        }
        foreach (var e in update.WatchedLeft)
        {
            Toast(F("event.deviceLeft", e.Watched.Name), e.IpAddress, ToastKind.Warning);
            NotifySystem(F("event.deviceLeft", e.Watched.Name), F("notify.lastSeenAt", e.IpAddress));
        }

        var sourceProblem = result.Devices.SelectMany(d => d.Services)
            .Any(s => s.VulnerabilityCheck is VulnerabilityCheckStatus.SourceUnavailable or VulnerabilityCheckStatus.CheckedWithStaleData);
        if (sourceProblem)
            Toast(T("check.unavailable"), T("toast.nvd.hint"), ToastKind.Warning);
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
        ? T("devices.subtitle.searching")
        : F("devices.subtitle.online", OnlineCount) + (OfflineCount > 0 && ShowOffline ? " · " + F("devices.subtitle.offline", OfflineCount) : "") + $" · {LastScanText.ToLower(Instance.Culture)}";

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
            Toast(T("toast.unwatched"), device.DisplayName, ToastKind.Info);
        }
        else
        {
            _tracker.Watch(device.Device, device.DisplayName);
            device.IsWatched = true;
            Toast(T("toast.watched"), F("toast.watched.hint", device.DisplayName), ToastKind.Success);
        }
        RebuildWatchlist();
    }

    [RelayCommand]
    private async Task CopyAsync(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text == "—")
            return;
        await _platform.CopyToClipboardAsync(text);
        Toast(T("toast.copied"), text, ToastKind.Success);
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
        ? T("security.subtitle.waiting")
        : !SecurityChecked
        ? T("security.subtitle.off")
        : AllVulnerabilities.Count == 0
            ? T("security.allClear.hint")
            : F("security.subtitle.count", AllVulnerabilities.Count, Plural("security.subtitle.devices", VulnerableDeviceCount));

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
        !Visuals.IsUnknownVendor(h.Vendor) ? Visuals.VendorLabel(h.Vendor) : h.IpAddress;

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
        var path = await _platform.PickSaveFileAsync(T("export.dialog.devices"), $"{T("export.file.devices")}-{DateTime.Now:yyyyMMdd-HHmm}.csv", "csv", "CSV");
        if (path == null)
            return;
        try
        {
            ExportService.ExportToCsv(_lastResult.Devices, path);
            Toast(T("toast.exported"), Path.GetFileName(path), ToastKind.Success);
        }
        catch (Exception ex)
        {
            Toast(T("toast.export.failed"), ex.Message, ToastKind.Danger);
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

        var path = await _platform.PickSaveFileAsync(T("export.dialog.report"), $"{T("export.file.report")}-{DateTime.Now:yyyyMMdd-HHmm}.{ext}", ext, label);
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
            Toast(T("toast.report.saved"), Path.GetFileName(path), ToastKind.Success);
        }
        catch (Exception ex)
        {
            Toast(T("toast.report.failed"), ex.Message, ToastKind.Danger);
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
        Toast(T("toast.unexpected"), F("toast.unexpected.hint", ex.Message, CrashLog.Directory), ToastKind.Danger);

    [RelayCommand]
    private void DismissToast(ToastViewModel? toast)
    {
        if (toast != null)
            Toasts.Remove(toast);
    }
}

/// <summary>Opção de idioma. Classe (não record): a identidade não muda e o texto atualiza-se sozinho.</summary>
public sealed class LanguageOption(string code) : ObservableObject
{
    public string Code { get; } = code;

    public string Label => Code switch
    {
        "pt" => "Português",
        "en" => "English",
        // "Automático" segue o Windows: mostrar o idioma do sistema, não o que está escolhido agora.
        _ => F("language.auto", Loc.SystemLanguage() == "pt" ? "Português" : "English")
    };

    public void Refresh() => OnPropertyChanged(nameof(Label));
    public override string ToString() => Label;
}

public sealed class IntervalOption(int seconds) : ObservableObject
{
    public int Seconds { get; } = seconds;
    public string Label => Plural("interval.minutes", Seconds / 60);
    public void Refresh() => OnPropertyChanged(nameof(Label));
    public override string ToString() => Label;
}
