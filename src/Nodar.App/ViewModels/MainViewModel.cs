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

/// <summary>
/// Coordena a janela principal: scan, lista de dispositivos, filtros e navegação. As preferências, os avisos e as
/// vistas de Segurança, Histórico e Monitorizados vivem em view-models próprios (<see cref="Settings"/>,
/// <see cref="Notifications"/>, <see cref="Security"/>, <see cref="History"/>, <see cref="Watchlist"/>).
/// </summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly IPlatformServices _platform;
    private readonly DeviceTracker _tracker;
    private readonly KnownDevices _known;
    private readonly DispatcherTimer _refreshTimer = new();
    private readonly DispatcherTimer _clockTimer = new() { Interval = TimeSpan.FromSeconds(30) };
    private CancellationTokenSource? _scanCts;
    private ScanResult? _lastResult;
    private DateTime? _lastScanAt;
    private List<DeviceItemViewModel> _allDevices = [];
    private IReadOnlyList<DeviceInfo>? _preliminary;

    public MainViewModel(IPlatformServices platform)
    {
        _platform = platform;
        var dataDirectory = DemoData.IsEnabled ? DemoData.DataDirectory : DeviceTracker.DefaultDataDirectory;
        _tracker = new DeviceTracker(dataDirectory);
        _tracker.Load();

        // O que o utilizador decidiu sobre cada dispositivo (conhecido, suspeito, nome, nota): só neste PC.
        _known = new KnownDevices(dataDirectory);
        _known.Load();
        Review = new DeviceReviewViewModel(_known);
        Review.Changed += RebuildDevices;
        Review.AllMarkedKnown += count => Toast(T("review.marked"), Plural("review.marked.hint", count), ToastKind.Success);

        // As preferências são carregadas (e o idioma aplicado) antes de ouvir mudanças de idioma.
        Settings = new SettingsViewModel(AppSettings.Load());
        Settings.ShowOfflineChanged += RebuildDevices;
        Settings.RefreshScheduleChanged += ConfigureRefreshTimer;
        Settings.StartupRegistrationFailed += () =>
            Toast(T("toast.startup.failed"), T("toast.startup.failed.hint"), ToastKind.Warning);
        Instance.LanguageChanged += OnLanguageChanged;

        Security = new SecurityViewModel();
        var gatewayGuard = new GatewayGuard(dataDirectory);
        gatewayGuard.Load();
        var portMappings = new PortMappingTracker(dataDirectory);
        portMappings.Load();
        Exposure = new ExposureViewModel(gatewayGuard, portMappings, DemoData.IsEnabled ? DemoData.LookupInternetAsync : null);
        Exposure.GatewayTrusted += () => Toast(T("toast.gateway.trusted"), T("toast.gateway.trusted.hint"), ToastKind.Success);
        History = new HistoryViewModel(_tracker, _known);
        Watchlist = new WatchlistViewModel(_tracker);

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

    /// <summary>Preferências do utilizador (opções de scan, atualização automática, segundo plano, idioma).</summary>
    public SettingsViewModel Settings { get; }

    /// <summary>Vista de Segurança.</summary>
    public SecurityViewModel Security { get; }

    /// <summary>O que a rede expõe: portas abertas pelo router, MAC do router e o que a internet vê.</summary>
    public ExposureViewModel Exposure { get; }

    /// <summary>Dizer quais são os dispositivos: "é meu", "não reconheço", nome e nota.</summary>
    public DeviceReviewViewModel Review { get; }

    /// <summary>Vista de Histórico.</summary>
    public HistoryViewModel History { get; }

    /// <summary>Vista de Monitorizados.</summary>
    public WatchlistViewModel Watchlist { get; }

    /// <summary>Avisos dentro da app.</summary>
    public ToastHost Notifications { get; } = new();

    /// <summary>Chamado quando a janela abre: primeiro scan imediato.</summary>
    public async Task StartAsync()
    {
        if (_started)
            return;
        _started = true;
        if (DemoData.IsEnabled)
            DemoData.SeedKnownDevices(_known); // estado inventado, já no idioma escolhido
        await ScanAsync();
    }

    private bool _started;

    // ================================================================ Idioma

    private bool _refreshPending;

    /// <summary>
    /// O idioma mudou. As listas das caixas de seleção nunca são recriadas (isso limpava a seleção e
    /// provocava um ciclo pt↔en que bloqueava a app): só os textos das opções são atualizados. O resto da
    /// interface é refeito depois de a caixa de seleção terminar o seu evento.
    /// </summary>
    private void OnLanguageChanged()
    {
        Settings.RefreshLabels();
        foreach (var chip in FilterChips)
            chip.Refresh();

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
            OnPropertyChanged(nameof(LastScanText));
            OnPropertyChanged(nameof(ScanModeSummary));
        }, Avalonia.Threading.DispatcherPriority.Background);
    }

    // ================================================================ Segundo plano e notificações do Windows

    /// <summary>Notificação do Windows, só quando o utilizador não está a ver a janela.</summary>
    private void NotifySystem(string title, string message)
    {
        if (Settings.WindowsNotifications && !_platform.IsUserLooking)
            _platform.NotifySystem(title, message);
    }

    /// <summary>A janela foi fechada mas a app continua na bandeja: explicar isso uma vez.</summary>
    public void OnHiddenToTray()
    {
        if (Settings.TrayHintShown)
            return;
        Settings.MarkTrayHintShown();
        _platform.NotifySystem(T("tray.hint.title"),
            Settings.AutoRefresh ? T("tray.hint.autoRefresh") : T("tray.hint.manual"));
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
        Page.Security => Security.Subtitle,
        Page.History => Plural("history.subtitle", _tracker.History.Count),
        Page.Watchlist => Watchlist.Items.Count == 0 ? T("watch.subtitle.empty") : Plural("watch.subtitle", Watchlist.Items.Count),
        _ => DevicesSubtitle
    };

    [RelayCommand]
    private void Navigate(Page page) => CurrentPage = page;

    // ================================================================ Atualização automática

    private void ConfigureRefreshTimer()
    {
        _refreshTimer.Stop();
        if (!Settings.AutoRefresh)
            return;
        _refreshTimer.Interval = Settings.RefreshInterval;
        _refreshTimer.Start();
    }

    /// <summary>As opções de scan em texto (atualiza-se quando um scan arranca e quando o idioma muda).</summary>
    public string ScanModeSummary => Settings.ScanModeSummary;

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
                DeepScan = Settings.DeepScan,
                PortScan = Settings.PortScan,
                OSDetection = Settings.OsDetection,
                ServiceDetection = Settings.ServiceDetection,
                VulnerabilityScan = Settings.VulnerabilityScan,
                UpnpCheck = Settings.UpnpCheck,
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
            var exposure = Exposure.ApplyScan(result);
            RebuildDevices();
            RebuildWatchlist();
            AnnounceChanges(update, result);
            AnnounceExposure(exposure);
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

        AnnounceReturned(update.Returned);

        var sourceProblem = result.Devices.SelectMany(d => d.Services)
            .Any(s => s.VulnerabilityCheck is VulnerabilityCheckStatus.SourceUnavailable or VulnerabilityCheckStatus.CheckedWithStaleData);
        if (sourceProblem)
            Toast(T("check.unavailable"), T("toast.nvd.hint"), ToastKind.Warning);
    }

    /// <summary>
    /// Dispositivos que voltaram à rede e que o utilizador não conhece (por rever, depois de ter começado a
    /// marcar os seus) ou que marcou como "não reconheço". Os dispositivos conhecidos nunca geram este aviso.
    /// </summary>
    internal void AnnounceReturned(IReadOnlyList<DeviceInfo> returned)
    {
        string Line(DeviceInfo d) => $"{FindItem(d)?.DisplayName ?? d.IpAddress} · {d.IpAddress}";

        var suspicious = new List<DeviceInfo>();
        var unknown = new List<DeviceInfo>();
        foreach (var device in returned)
        {
            switch (_known.Attention(_tracker.Key(device)))
            {
                case DeviceAttention.Suspicious: suspicious.Add(device); break;
                case DeviceAttention.Unknown: unknown.Add(device); break;
            }
        }

        foreach (var device in suspicious)
        {
            Toast(T("review.suspicious.back"), Line(device), ToastKind.Danger);
            NotifySystem(T("review.suspicious.back"), Line(device));
        }

        if (unknown.Count == 1)
        {
            Toast(T("review.unknown.back"), Line(unknown[0]), ToastKind.Warning);
            NotifySystem(T("review.unknown.back"), Line(unknown[0]));
        }
        else if (unknown.Count > 1)
        {
            var title = F("review.unknown.back.many", unknown.Count);
            Toast(title, "", ToastKind.Warning);
            NotifySystem(title, string.Join("\n", unknown.Take(4).Select(Line)) + (unknown.Count > 4 ? "\n…" : ""));
        }
    }

    /// <summary>Portas novas abertas pelo router e alerta do MAC do router.</summary>
    private void AnnounceExposure(ExposureChanges changes)
    {
        string Describe(PortMapping m)
        {
            var item = _allDevices.FirstOrDefault(d => d.IsOnline && d.IpAddress == m.InternalClient);
            var target = item != null && item.DisplayName != m.InternalClient ? $"{item.DisplayName} · {m.InternalClient}" : m.InternalClient;
            return $"{m.Protocol} {m.ExternalPort} → {target}";
        }

        var ports = changes.NewMappings;
        foreach (var mapping in ports.Take(3))
            Toast(T("notify.portOpened"), Describe(mapping),
                ExposureAdvice.SensitiveService(mapping.InternalPort) != null ? ToastKind.Danger : ToastKind.Warning);
        if (ports.Count > 3)
            Toast(F("notify.morePorts", ports.Count - 3), "", ToastKind.Warning);
        // No Windows, só o que interessa (portas temporárias de jogos e chamadas ficam só dentro da app).
        var worth = ports.Where(ExposureAdvice.WorthSystemNotice).ToList();
        if (worth.Count == 1)
            NotifySystem(T("notify.portOpened"), Describe(worth[0]));
        else if (worth.Count > 1)
            NotifySystem(F("notify.portsOpened", worth.Count),
                string.Join("\n", worth.Take(4).Select(Describe)) + (worth.Count > 4 ? "\n…" : ""));

        if (changes.NewGatewayAlert is not { } alert)
            return;
        if (alert.IsStrong)
        {
            // O sinal forte justifica incomodar mesmo com a janela fechada; a mudança simples só fica na app
            // (acontece sempre que se muda de rede com o mesmo endereço de router).
            var message = F("notify.gateway.strong", alert.GatewayIp, alert.OtherDeviceIp);
            Toast(T("gateway.strong.title"), message, ToastKind.Danger);
            NotifySystem(T("gateway.strong.title"), message);
        }
        else
        {
            Toast(T("gateway.weak.title"), F("notify.gateway.weak", alert.GatewayIp), ToastKind.Warning);
        }
    }

    // ================================================================ Dispositivos

    public ObservableCollection<DeviceItemViewModel> Devices { get; } = [];

    [ObservableProperty] private string _searchText = "";
    partial void OnSearchTextChanged(string value) => ApplyFilter();

    // ================================================================ Filtros por tipo e estado

    /// <summary>Pílulas de filtro acima da lista (só os grupos que existem na rede, com contagem).</summary>
    public ObservableCollection<FilterChipViewModel> FilterChips { get; } = [];

    [ObservableProperty] private string _selectedFilter = DeviceFilters.All;

    public bool HasFilterChips => FilterChips.Count > 2; // "Todos" + pelo menos dois grupos

    partial void OnSelectedFilterChanged(string value)
    {
        foreach (var chip in FilterChips)
            chip.IsSelected = chip.Key == value;
        ApplyFilter();
    }

    [RelayCommand]
    private void SelectFilter(string? key)
    {
        // Voltar a tocar no filtro ativo desliga-o (volta a "Todos").
        SelectedFilter = key == null || key == SelectedFilter ? DeviceFilters.All : key;
    }

    private void RebuildFilterChips()
    {
        var counts = new List<(string Key, int Count)> { (DeviceFilters.All, _allDevices.Count) };
        counts.AddRange(DeviceFilters.TypeGroups
            .Select(g => (g, _allDevices.Count(d => d.Group == g)))
            .Where(x => x.Item2 > 0));
        counts.AddRange(DeviceFilters.StateFilters
            .Select(f => (f, _allDevices.Count(d => DeviceFilters.Matches(d, f))))
            .Where(x => x.Item2 > 0));

        // Se o filtro escolhido deixou de existir (ex.: já não há offline), voltar a "Todos".
        if (counts.All(c => c.Key != SelectedFilter))
            SelectedFilter = DeviceFilters.All; // a lista é refeita logo a seguir

        var same = FilterChips.Select(c => c.Key).SequenceEqual(counts.Select(c => c.Key));
        if (same)
        {
            for (var i = 0; i < counts.Count; i++)
                FilterChips[i].Count = counts[i].Count;
        }
        else
        {
            FilterChips.Clear();
            foreach (var (key, count) in counts)
                FilterChips.Add(new FilterChipViewModel(key, count));
        }
        foreach (var chip in FilterChips)
            chip.IsSelected = chip.Key == SelectedFilter;
        OnPropertyChanged(nameof(SelectedFilter));
        OnPropertyChanged(nameof(HasFilterChips));
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    private DeviceItemViewModel? _selectedDevice;

    partial void OnSelectedDeviceChanged(DeviceItemViewModel? value) => Review.Select(value);

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
        : F("devices.subtitle.online", OnlineCount) + (OfflineCount > 0 && Settings.ShowOffline ? " · " + F("devices.subtitle.offline", OfflineCount) : "") + $" · {LastScanText.ToLower(Instance.Culture)}"
          + (Review.IsActive && Review.UnreviewedCount > 0 ? " · " + Plural("review.subtitle", Review.UnreviewedCount) : "");

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
                    isNew: _tracker.IsRecentlyNew(history, TimeSpan.FromHours(24)),
                    label: _known.Find(key), attention: _known.Attention(key)));
            }
        }

        var offline = _tracker.OfflineEntries().ToList();
        OfflineCount = offline.Count;
        if (Settings.ShowOffline)
        {
            var onlineKeys = items.Select(i => i.Key).ToHashSet();
            foreach (var entry in offline)
            {
                var device = HistoryViewModel.FromHistory(entry);
                if (onlineKeys.Contains(_tracker.Key(device)))
                    continue;
                items.Add(new DeviceItemViewModel(device, entry, _tracker.Key(device), isGateway: false, isOnline: false,
                    isWatched: _tracker.FindWatched(device) != null,
                    label: _known.Find(_tracker.Key(device)), attention: _known.Attention(_tracker.Key(device))));
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

        RebuildFilterChips();
        ApplyFilter();
        SelectedDevice = selectedKey == null ? null : Devices.FirstOrDefault(d => d.Key == selectedKey);
        RebuildSecurity();
        RebuildHistory();
        Review.Refresh(_allDevices, source != null,
            [.. _tracker.History.Select(h => _tracker.Key(h.MacAddress, h.IpAddress))]);

        OnPropertyChanged(nameof(DevicesSubtitle));
        OnPropertyChanged(nameof(PageSubtitle));
        OnPropertyChanged(nameof(ShowFirstScan));
    }

    private void ApplyFilter()
    {
        var selected = SelectedDevice;
        Devices.Clear();
        foreach (var d in _allDevices.Where(d => d.Matches(SearchText) && DeviceFilters.Matches(d, SelectedFilter)))
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
        RefreshWatchedFilter();
    }

    /// <summary>A contagem de "Monitorizados" mudou: refazer as pílulas e, se esse filtro está ativo, a lista.</summary>
    private void RefreshWatchedFilter()
    {
        RebuildFilterChips();
        if (SelectedFilter == "watched")
            ApplyFilter();
    }

    /// <summary>Só para testes: mostrar um resultado de scan sem analisar a rede.</summary>
    internal void ShowScanResultForTests(ScanResult result)
    {
        _lastResult = result;
        _lastScanAt = DateTime.Now;
        _tracker.ApplyScan(result.Devices);
        Exposure.ApplyScan(result);
        RebuildDevices();
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

    private static long IpSortKey(string ip) =>
        System.Net.IPAddress.TryParse(ip, out var a) && a.GetAddressBytes() is { Length: 4 } b
            ? ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3]
            : long.MaxValue;

    // ================================================================ Segurança, histórico e monitorizados

    private void RebuildSecurity()
    {
        Security.Update(_lastResult, _allDevices, VulnerableDeviceCount);
        Exposure.Update(_allDevices);
    }

    private void RebuildHistory() => History.Update(_allDevices);

    private void RebuildWatchlist()
    {
        Watchlist.Update(_lastResult?.Devices ?? new List<DeviceInfo>());
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
        RefreshWatchedFilter();
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

    // ================================================================ Avisos

    private void Toast(string title, string message, ToastKind kind) => Notifications.Show(title, message, kind);

    public void ReportUnexpectedError(Exception ex) =>
        Toast(T("toast.unexpected"), F("toast.unexpected.hint", ex.Message, CrashLog.Directory), ToastKind.Danger);
}
