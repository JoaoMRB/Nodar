using System.IO;
using System.Text.Json;
using NetworkScanner.Models;
using NetworkScanner.Services;
using NetworkScanner.UI;

namespace NetworkScanner;

public sealed class MainForm : Form
{
    private readonly Panel _headerPanel = new();
    private readonly Panel _networkPanel = new();
    private readonly Panel _toolbarPanel = new();
    private readonly Panel _statusPanel = new();
    private readonly Panel _contentPanel = new();
    private readonly Panel _detailsPanel = new();
    private readonly TableLayoutPanel _contentLayout = new();
    private readonly DataGridView _grid = new();
    private readonly ListBox _historyList = new();
    private readonly Label _detailsTitle = new();
    private readonly Label _detailsSubtitle = new();
    private readonly ProgressBar _progressBar = new();
    private readonly Label _statusLabel = new();
    private readonly Label _deviceCountLabel = new();
    private readonly Label _summaryLabel = new();
    private readonly Button _scanButton = new();
    private readonly Button _exportButton = new();
    private readonly CheckBox _deepScanCheck = new();
    private readonly CheckBox _portScanCheck = new();
    private readonly CheckBox _osDetectionCheck = new();
    private readonly CheckBox _serviceDetectionCheck = new();
    private readonly CheckBox _vulnScanCheck = new();
    private readonly CheckBox _autoRefreshCheck = new();
    private readonly CheckBox _showOfflineCheck = new();
    private readonly ComboBox _refreshInterval = new();
    private readonly ComboBox _timingTemplate = new();
    private readonly Label _searchLabel = new();
    private readonly TextBox _searchBox = new();
    private readonly System.Windows.Forms.Timer _refreshTimer = new();
    private readonly Label _adminLabel = new();
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };
    private readonly string _historyFilePath;

    private Panel? _cardIp, _cardNetwork, _cardGateway, _cardInterface, _cardHostname;
    private CancellationTokenSource? _scanCts;
    private HashSet<string> _knownDevices = [];
    private bool _isScanning;
    private List<DeviceInfo> _lastDevices = [];
    private string? _lastVulnerabilityNote;
    private readonly Dictionary<string, DeviceHistoryEntry> _history = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<WatchedDevice> _watchedDevices = [];
    private readonly string _watchlistFilePath;

    public MainForm()
    {
        var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nodar");
        _historyFilePath = Path.Combine(dataDir, "history.json");
        _watchlistFilePath = Path.Combine(dataDir, "watchlist.json");
        MigrateLegacyData(dataDir);
        InitializeComponent();
        LoadSavedHistory();
        LoadWatchlist();
        _autoRefreshCheck.Checked = true;
        _refreshInterval.SelectedIndex = 0;
        LoadNetworkInfo();
        SetupAutoRefresh();
    }

    /// <summary>
    /// Copia o histórico e a lista de monitorização da versão antiga ("Network Watcher Pro"),
    /// que os guardava numa pasta dependente do nome do produto e da versão.
    /// </summary>
    private static void MigrateLegacyData(string dataDir)
    {
        try
        {
            var legacyRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkScanner");
            if (!Directory.Exists(legacyRoot))
                return;

            Directory.CreateDirectory(dataDir);
            foreach (var fileName in new[] { "history.json", "watchlist.json" })
            {
                var target = Path.Combine(dataDir, fileName);
                if (File.Exists(target))
                    continue;

                var newest = Directory.EnumerateFiles(legacyRoot, fileName, SearchOption.AllDirectories)
                    .Where(f => Path.GetFileName(Path.GetDirectoryName(f)) == "NetworkWatcherPro")
                    .OrderByDescending(File.GetLastWriteTimeUtc)
                    .FirstOrDefault();

                if (newest != null)
                    File.Copy(newest, target);
            }
        }
        catch
        {
            // A migração é opcional: se falhar, a app arranca com dados vazios.
        }
    }

    private void InitializeComponent()
    {
        Text = "Nodar";
        Size = new Size(1100, 720);
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.Background;
        ForeColor = Theme.Text;
        Font = Theme.BodyFont;
        DoubleBuffered = true;

        BuildHeader();
        BuildNetworkCards();
        BuildToolbar();
        BuildGrid();
        BuildDetailsPanel();
        BuildStatusBar();

        _contentPanel.Dock = DockStyle.Fill;

        Controls.Add(_contentPanel);
        Controls.Add(_statusPanel);
        Controls.Add(_toolbarPanel);
        Controls.Add(_networkPanel);
        Controls.Add(_headerPanel);

        _exportButton.Enabled = false;
    }

    private void BuildHeader()
    {
        _headerPanel.Dock = DockStyle.Top;
        _headerPanel.Height = 72;
        _headerPanel.BackColor = Theme.Background;
        _headerPanel.Padding = new Padding(20, 16, 20, 8);

        var title = new Label
        {
            Text = "📡  Nodar",
            Font = Theme.TitleFont,
            ForeColor = Theme.Text,
            AutoSize = true,
            Location = new Point(20, 16)
        };

        var subtitle = new Label
        {
            Text = "Descobre o teu gateway e os dispositivos ligados à rede local",
            Font = Theme.SubtitleFont,
            ForeColor = Theme.TextMuted,
            AutoSize = true,
            Location = new Point(52, 42)
        };

        _scanButton.Text = "🔍  Analisar Rede";
        _scanButton.Size = new Size(160, 40);
        _scanButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        Theme.StyleButton(_scanButton, primary: true);
        _scanButton.Click += async (_, _) => await RunScanAsync();

        _adminLabel.Font = Theme.SmallFont;
        _adminLabel.ForeColor = Theme.Warning;
        _adminLabel.AutoSize = true;
        _adminLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;

        if (!NetworkDiscoveryService.IsAdministrator())
        {
            _adminLabel.Text = "⚠ Executa como Admin para melhores resultados";
        }

        _headerPanel.Resize += (_, _) =>
        {
            _scanButton.Location = new Point(_headerPanel.Width - _scanButton.Width - 20, 16);
            _adminLabel.Location = new Point(_headerPanel.Width - _adminLabel.Width - 20, 48);
        };

        _headerPanel.Controls.Add(title);
        _headerPanel.Controls.Add(subtitle);
        _headerPanel.Controls.Add(_scanButton);
        _headerPanel.Controls.Add(_adminLabel);

        _scanButton.Location = new Point(_headerPanel.Width - 180, 16);
        _adminLabel.Location = new Point(_headerPanel.Width - 280, 48);
    }

    private void BuildNetworkCards()
    {
        _networkPanel.Dock = DockStyle.Top;
        _networkPanel.Height = 90;
        _networkPanel.BackColor = Theme.Background;
        _networkPanel.Padding = new Padding(16, 0, 16, 8);

        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            AutoScroll = true,
            BackColor = Theme.Background
        };

        _cardIp = Theme.CreateInfoCard("Teu IP", "—");
        _cardNetwork = Theme.CreateInfoCard("Rede", "—");
        _cardGateway = Theme.CreateInfoCard("Gateway", "—");
        _cardInterface = Theme.CreateInfoCard("Interface", "—");
        _cardHostname = Theme.CreateInfoCard("Hostname", "—");

        flow.Controls.AddRange([_cardIp, _cardNetwork, _cardGateway, _cardInterface, _cardHostname]);
        _networkPanel.Controls.Add(flow);
    }

    private void BuildToolbar()
    {
        _toolbarPanel.Dock = DockStyle.Top;
        _toolbarPanel.Height = 52;
        _toolbarPanel.BackColor = Theme.Surface;
        _toolbarPanel.Padding = new Padding(16, 10, 16, 10);

        var flowPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            AutoScroll = false,
            BackColor = Theme.Surface,
            Margin = new Padding(0),
            Padding = new Padding(0)
        };

        _deepScanCheck.Text = "Scan profundo";
        _deepScanCheck.Margin = new Padding(0, 0, 20, 0);
        Theme.StyleCheckBox(_deepScanCheck);

        _portScanCheck.Text = "Analisar portas";
        _portScanCheck.Margin = new Padding(0, 0, 20, 0);
        Theme.StyleCheckBox(_portScanCheck);

        _osDetectionCheck.Text = "Detetar OS";
        _osDetectionCheck.Margin = new Padding(0, 0, 20, 0);
        Theme.StyleCheckBox(_osDetectionCheck);

        _serviceDetectionCheck.Text = "Serviços";
        _serviceDetectionCheck.Margin = new Padding(0, 0, 20, 0);
        Theme.StyleCheckBox(_serviceDetectionCheck);

        _vulnScanCheck.Text = "Vulnerabilidades";
        _vulnScanCheck.Margin = new Padding(0, 0, 20, 0);
        Theme.StyleCheckBox(_vulnScanCheck);

        _autoRefreshCheck.Text = "Auto-atualizar";
        _autoRefreshCheck.Margin = new Padding(0, 0, 10, 0);
        Theme.StyleCheckBox(_autoRefreshCheck);
        _autoRefreshCheck.CheckedChanged += (_, _) => SetupAutoRefresh();

        _showOfflineCheck.Text = "Mostrar offline";
        _showOfflineCheck.Margin = new Padding(0, 0, 20, 0);
        Theme.StyleCheckBox(_showOfflineCheck);
        _showOfflineCheck.CheckedChanged += (_, _) => RefreshGrid();

        var watchlistButton = new Button
        {
            Text = "⭐  Monitorizar",
            Size = new Size(120, 32),
            Margin = new Padding(0, 0, 15, 0)
        };
        Theme.StyleButton(watchlistButton);
        watchlistButton.Click += WatchlistButton_Click;

        var auditReportButton = new Button
        {
            Text = "📋  Relatório",
            Size = new Size(110, 32),
            Margin = new Padding(0, 0, 15, 0)
        };
        Theme.StyleButton(auditReportButton);
        auditReportButton.Click += AuditReportButton_Click;

        var showDetailsButton = new Button
        {
            Text = "🔍  Detalhes",
            Size = new Size(100, 32),
            Margin = new Padding(0, 0, 15, 0)
        };
        Theme.StyleButton(showDetailsButton);
        showDetailsButton.Click += ShowDetailsButton_Click;

        _refreshInterval.DropDownStyle = ComboBoxStyle.DropDownList;
        _refreshInterval.BackColor = Theme.SurfaceLight;
        _refreshInterval.ForeColor = Theme.Text;
        _refreshInterval.FlatStyle = FlatStyle.Flat;
        _refreshInterval.Items.AddRange(["10 seg", "30 seg", "60 seg"]);
        _refreshInterval.SelectedIndex = 1;
        _refreshInterval.Size = new Size(85, 26);
        _refreshInterval.Margin = new Padding(0, 0, 30, 0);
        _refreshInterval.SelectedIndexChanged += (_, _) => SetupAutoRefresh();

        _timingTemplate.DropDownStyle = ComboBoxStyle.DropDownList;
        _timingTemplate.BackColor = Theme.SurfaceLight;
        _timingTemplate.ForeColor = Theme.Text;
        _timingTemplate.FlatStyle = FlatStyle.Flat;
        _timingTemplate.Items.AddRange(["Normal", "Polite", "Aggressive", "Insane", "Sneaky", "Paranoid"]);
        _timingTemplate.SelectedIndex = 0;
        _timingTemplate.Size = new Size(90, 26);
        _timingTemplate.Margin = new Padding(0, 0, 30, 0);

        _searchLabel.Text = "Buscar:";
        _searchLabel.ForeColor = Theme.Text;
        _searchLabel.Font = Theme.BodyFont;
        _searchLabel.AutoSize = true;
        _searchLabel.Margin = new Padding(0, 0, 5, 0);

        _searchBox.Size = new Size(160, 26);
        _searchBox.BackColor = Theme.SurfaceLight;
        _searchBox.ForeColor = Theme.Text;
        _searchBox.BorderStyle = BorderStyle.FixedSingle;
        _searchBox.Margin = new Padding(0, 0, 30, 0);
        _searchBox.TextChanged += (_, _) => ApplyFilter();

        _summaryLabel.Text = "Aguardando análise...";
        _summaryLabel.ForeColor = Theme.Text;
        _summaryLabel.Font = Theme.SmallFont;
        _summaryLabel.AutoSize = true;
        _summaryLabel.Margin = new Padding(0, 0, 15, 0);

        _deviceCountLabel.Text = "0 dispositivos";
        _deviceCountLabel.ForeColor = Theme.Primary;
        _deviceCountLabel.Font = new Font("Segoe UI Semibold", 9.5F);
        _deviceCountLabel.AutoSize = true;
        _deviceCountLabel.Margin = new Padding(0, 0, 15, 0);

        _exportButton.Text = "📥  Exportar CSV";
        _exportButton.Size = new Size(130, 32);
        Theme.StyleButton(_exportButton);
        _exportButton.Click += ExportButton_Click;
        _exportButton.Margin = new Padding(0);

        flowPanel.Controls.AddRange([
            _deepScanCheck, _portScanCheck, _osDetectionCheck, _serviceDetectionCheck, _vulnScanCheck,
            _autoRefreshCheck, _showOfflineCheck, watchlistButton, auditReportButton, showDetailsButton, _timingTemplate, _refreshInterval, _searchLabel, _searchBox, _summaryLabel, _deviceCountLabel, _exportButton
        ]);

        _toolbarPanel.Controls.Add(flowPanel);
    }

    private void BuildGrid()
    {
        _contentPanel.Dock = DockStyle.Fill;
        _contentPanel.Padding = new Padding(10, 8, 10, 8);
        _contentPanel.BackColor = Theme.Background;
        _contentPanel.Margin = new Padding(0);

        _contentLayout.Dock = DockStyle.Fill;
        _contentLayout.BackColor = Theme.Background;
        _contentLayout.ColumnCount = 2;
        _contentLayout.RowCount = 1;
        _contentLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        _contentLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250F));
        _contentLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

        var gridHost = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Theme.Background
        };

        _grid.Dock = DockStyle.Fill;
        _grid.Margin = new Padding(0, 0, 6, 0);
        Theme.StyleDataGridView(_grid);

        _grid.Columns.AddRange(
            new DataGridViewTextBoxColumn { Name = "Ip", HeaderText = "IP", FillWeight = 10 },
            new DataGridViewTextBoxColumn { Name = "Mac", HeaderText = "MAC", FillWeight = 12 },
            new DataGridViewTextBoxColumn { Name = "Hostname", HeaderText = "Hostname", FillWeight = 14 },
            new DataGridViewTextBoxColumn { Name = "Vendor", HeaderText = "Fabricante", FillWeight = 10 },
            new DataGridViewTextBoxColumn { Name = "OS", HeaderText = "OS", FillWeight = 10 },
            new DataGridViewTextBoxColumn { Name = "Type", HeaderText = "Tipo", FillWeight = 8 },
            new DataGridViewTextBoxColumn { Name = "Status", HeaderText = "Estado", FillWeight = 7 },
            new DataGridViewTextBoxColumn { Name = "LastSeen", HeaderText = "Visto há", FillWeight = 8 },
            new DataGridViewTextBoxColumn { Name = "Ports", HeaderText = "Portas", FillWeight = 10 },
            new DataGridViewTextBoxColumn { Name = "Services", HeaderText = "Serviços", FillWeight = 8 },
            new DataGridViewTextBoxColumn { Name = "Vulns", HeaderText = "Vulns", FillWeight = 6 },
            new DataGridViewTextBoxColumn { Name = "Local", HeaderText = "Este PC", FillWeight = 7 }
        );

        _grid.CellFormatting += Grid_CellFormatting;
        _grid.CellDoubleClick += Grid_CellDoubleClick;
        _grid.SelectionChanged += Grid_SelectionChanged;

        gridHost.Controls.Add(_grid);
        _contentLayout.Controls.Add(gridHost, 0, 0);
        _contentLayout.Controls.Add(_detailsPanel, 1, 0);
        _contentPanel.Controls.Add(_contentLayout);
    }

    private void LoadSavedHistory()
    {
        try
        {
            if (!File.Exists(_historyFilePath))
                return;

            var json = File.ReadAllText(_historyFilePath);
            var entries = JsonSerializer.Deserialize<List<DeviceHistoryEntry>>(json, _jsonOptions);
            if (entries == null)
                return;

            _history.Clear();
            foreach (var entry in entries)
            {
                if (!string.IsNullOrWhiteSpace(entry.IpAddress))
                    _history[entry.IpAddress] = entry;
            }
        }
        catch { }
    }

    private void LoadWatchlist()
    {
        try
        {
            if (!File.Exists(_watchlistFilePath))
                return;

            var json = File.ReadAllText(_watchlistFilePath);
            var watched = JsonSerializer.Deserialize<List<WatchedDevice>>(json, _jsonOptions);
            if (watched == null)
                return;

            _watchedDevices.Clear();
            _watchedDevices.AddRange(watched);
        }
        catch { }
    }

    private void SaveWatchlist()
    {
        try
        {
            var directory = Path.GetDirectoryName(_watchlistFilePath);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(_watchedDevices, _jsonOptions);
            File.WriteAllText(_watchlistFilePath, json);
        }
        catch { }
    }

    private void SaveHistoryToDisk()
    {
        try
        {
            var directory = Path.GetDirectoryName(_historyFilePath);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            var json = JsonSerializer.Serialize(_history.Values.OrderBy(e => e.IpAddress).ToList(), _jsonOptions);
            File.WriteAllText(_historyFilePath, json);
        }
        catch { }
    }

    private void ApplyFilter()
    {
        var filter = _searchBox.Text.Trim();
        var visibleCount = 0;

        foreach (DataGridViewRow row in _grid.Rows)
        {
            if (row.Tag is not DeviceInfo device)
                continue;

            var visible = string.IsNullOrWhiteSpace(filter) ||
                          device.IpAddress.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                          device.MacAddress.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                          device.Hostname.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                          device.Vendor.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                          device.DeviceType.Contains(filter, StringComparison.OrdinalIgnoreCase);

            row.Visible = visible;
            if (visible) visibleCount++;
        }

        _deviceCountLabel.Text = filter.Length > 0
            ? $"{visibleCount}/{_grid.Rows.Count} visíveis"
            : $"{visibleCount} dispositivos";
    }

    private void BuildDetailsPanel()
    {
        _detailsPanel.Dock = DockStyle.Fill;
        _detailsPanel.BackColor = Theme.Surface;
        _detailsPanel.Padding = new Padding(12);
        _detailsPanel.Margin = new Padding(0, 0, 0, 0);
        _detailsPanel.BorderStyle = BorderStyle.FixedSingle;

        var title = new Label
        {
            Text = "Histórico",
            Font = new Font("Segoe UI Semibold", 11F),
            ForeColor = Theme.Text,
            AutoSize = true,
            Dock = DockStyle.Top
        };

        _detailsTitle.Text = "Selecione um dispositivo";
        _detailsTitle.Font = new Font("Segoe UI Semibold", 10F);
        _detailsTitle.ForeColor = Theme.Text;
        _detailsTitle.AutoSize = true;
        _detailsTitle.Dock = DockStyle.Top;
        _detailsTitle.Margin = new Padding(0, 12, 0, 6);

        _detailsSubtitle.Text = "O histórico aparece aqui quando selecionar um dispositivo da lista.";
        _detailsSubtitle.ForeColor = Theme.TextMuted;
        _detailsSubtitle.Font = Theme.SmallFont;
        _detailsSubtitle.Dock = DockStyle.Top;
        _detailsSubtitle.Margin = new Padding(0, 2, 0, 10);

        _historyList.Dock = DockStyle.Fill;
        _historyList.BackColor = Theme.SurfaceLight;
        _historyList.ForeColor = Theme.Text;
        _historyList.BorderStyle = BorderStyle.None;
        _historyList.Font = Theme.SmallFont;
        _historyList.Margin = new Padding(0, 8, 0, 0);
        _historyList.HorizontalExtent = 0;

        _detailsPanel.Controls.Add(_historyList);
        _detailsPanel.Controls.Add(_detailsSubtitle);
        _detailsPanel.Controls.Add(_detailsTitle);
        _detailsPanel.Controls.Add(title);
    }

    private void BuildStatusBar()
    {
        _statusPanel.Dock = DockStyle.Bottom;
        _statusPanel.Height = 44;
        _statusPanel.BackColor = Theme.Surface;
        _statusPanel.Padding = new Padding(16, 6, 16, 6);

        _statusLabel.Text = "Pronto para analisar";
        _statusLabel.ForeColor = Theme.TextMuted;
        _statusLabel.Font = Theme.SmallFont;
        _statusLabel.AutoSize = true;
        _statusLabel.Location = new Point(16, 12);

        _progressBar.Size = new Size(200, 8);
        _progressBar.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _progressBar.Style = ProgressBarStyle.Continuous;
        _progressBar.Visible = false;

        _statusPanel.Resize += (_, _) =>
        {
            _progressBar.Location = new Point(_statusPanel.Width - 220, 14);
        };

        _statusPanel.Controls.Add(_statusLabel);
        _statusPanel.Controls.Add(_progressBar);
        _progressBar.Location = new Point(860, 18);
    }

    private void Grid_SelectionChanged(object? sender, EventArgs e)
    {
        if (_grid.CurrentRow?.Tag is not DeviceInfo device)
        {
            _detailsTitle.Text = "Selecione um dispositivo";
            _detailsSubtitle.Text = "O histórico aparece aqui quando selecionar um dispositivo da lista.";
            _historyList.Items.Clear();
            return;
        }

        _detailsTitle.Text = device.DisplayName;
        _detailsSubtitle.Text = $"{device.IpAddress} · {device.MacAddress}";

        if (_history.TryGetValue(device.IpAddress, out var historyEntry) && historyEntry.Events.Count > 0)
        {
            _historyList.Items.Clear();
            foreach (var historyEvent in historyEntry.Events.OrderByDescending(x => x.Timestamp))
            {
                var text = historyEvent.EventType == DeviceHistoryEventType.Seen
                    ? $"Visto às {historyEvent.Timestamp:dd/MM HH:mm:ss} · {historyEvent.Status}"
                    : $"Saiu às {historyEvent.Timestamp:dd/MM HH:mm:ss} · {historyEvent.Status}";
                _historyList.Items.Add(text);
            }
        }
        else
        {
            _historyList.Items.Clear();
            _historyList.Items.Add("Sem eventos registados ainda.");
        }
    }

    private void Grid_CellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.RowIndex < 0) return;

        var row = _grid.Rows[e.RowIndex];
        if (row.Tag is DeviceInfo device && device.IsLocalDevice)
        {
            e.CellStyle!.ForeColor = Theme.Success;
            e.CellStyle.Font = new Font(Theme.BodyFont, FontStyle.Bold);
        }

        if (_grid.Columns[e.ColumnIndex].Name == "Status")
        {
            e.CellStyle!.ForeColor = row.Tag is DeviceInfo statusDevice && statusDevice.Status == "Offline"
                ? Theme.Danger
                : Theme.Success;
        }
    }

    private void LoadNetworkInfo()
    {
        var network = NetworkDiscoveryService.GetLocalNetwork();
        if (network == null)
        {
            _statusLabel.Text = "Não foi possível detetar a rede local";
            _statusLabel.ForeColor = Theme.Danger;
            return;
        }

        if (_cardIp != null) Theme.UpdateInfoCard(_cardIp, network.IpAddress);
        if (_cardNetwork != null) Theme.UpdateInfoCard(_cardNetwork, network.NetworkRange);
        if (_cardGateway != null) Theme.UpdateInfoCard(_cardGateway, network.Gateway);
        if (_cardInterface != null) Theme.UpdateInfoCard(_cardInterface, network.InterfaceName);
        if (_cardHostname != null) Theme.UpdateInfoCard(_cardHostname, network.Hostname);
    }

    private void SetupAutoRefresh()
    {
        _refreshTimer.Stop();
        
        if (_autoRefreshCheck.Checked)
        {
            var seconds = _refreshInterval.SelectedIndex switch
            {
                0 => 10,
                2 => 60,
                _ => 30
            };
            _refreshTimer.Interval = seconds * 1000;
            _refreshTimer.Tick += RefreshTimer_Tick;
            _refreshTimer.Start();
        }
        else
        {
            _refreshTimer.Tick -= RefreshTimer_Tick;
        }
    }

    private async void RefreshTimer_Tick(object? sender, EventArgs e)
    {
        if (!_isScanning)
            await RunScanAsync();
    }

    private async Task RunScanAsync()
    {
        if (_isScanning) return;

        _isScanning = true;
        _scanCts?.Cancel();
        _scanCts = new CancellationTokenSource();

        _scanButton.Enabled = false;
        _scanButton.Text = "⏳  A analisar...";
        _progressBar.Visible = true;
        _progressBar.Value = 0;
        _statusLabel.ForeColor = Theme.TextMuted;

        var progress = new Progress<ScanProgress>(p =>
        {
            _progressBar.Value = Math.Clamp(p.Percent, 0, 100);
            _statusLabel.Text = p.Message;
            _deviceCountLabel.Text = $"{p.DevicesFound} dispositivos";
        });

        try
        {
            var timingLevel = _timingTemplate.SelectedItem.ToString() switch
            {
                "Normal" => Services.TimingTemplates.TimingLevel.Normal,
                "Polite" => Services.TimingTemplates.TimingLevel.Polite,
                "Aggressive" => Services.TimingTemplates.TimingLevel.Aggressive,
                "Insane" => Services.TimingTemplates.TimingLevel.Insane,
                "Sneaky" => Services.TimingTemplates.TimingLevel.Sneaky,
                "Paranoid" => Services.TimingTemplates.TimingLevel.Paranoid,
                _ => Services.TimingTemplates.TimingLevel.Normal
            };

            var result = await Task.Run(() => NetworkDiscoveryService.ScanAsync(new ScanOptions
            {
                DeepScan = _deepScanCheck.Checked,
                PortScan = _portScanCheck.Checked,
                OSDetection = _osDetectionCheck.Checked,
                ServiceDetection = _serviceDetectionCheck.Checked,
                VulnerabilityScan = _vulnScanCheck.Checked,
                Progress = progress,
                CancellationToken = _scanCts.Token,
                TimingLevel = timingLevel
            }), _scanCts.Token);

            if (result.Error != null)
            {
                _statusLabel.Text = result.Error;
                _statusLabel.ForeColor = Theme.Danger;
                return;
            }

            DisplayDevices(result);
            DetectNewDevices(result.Devices);

            _lastVulnerabilityNote = result.VulnerabilitySourceNote;
            var vulnSourceProblem = result.Devices
                .SelectMany(d => d.Services)
                .Any(s => s.VulnerabilityCheck is VulnerabilityCheckStatus.SourceUnavailable or VulnerabilityCheckStatus.CheckedWithStaleData);

            _statusLabel.Text = $"Análise concluída em {result.Duration.TotalSeconds:F1}s · Método: {result.ScanMethod}" +
                                (vulnSourceProblem ? " · ⚠ NVD inacessível: vulnerabilidades incompletas" : "");
            _statusLabel.ForeColor = vulnSourceProblem ? Theme.Warning : Theme.Success;
            _exportButton.Enabled = result.Devices.Count > 0;
        }
        catch (OperationCanceledException)
        {
            _statusLabel.Text = "Análise cancelada";
            _statusLabel.ForeColor = Theme.Warning;
        }
        catch (Exception ex)
        {
            _statusLabel.Text = $"Erro: {ex.Message}";
            _statusLabel.ForeColor = Theme.Danger;
        }
        finally
        {
            _isScanning = false;
            _scanButton.Enabled = true;
            _scanButton.Text = "🔍  Analisar Rede";
            _progressBar.Visible = false;
        }
    }

    private void DisplayDevices(ScanResult result)
    {
        _grid.Rows.Clear();

        var previousDevices = _lastDevices
            .Where(d => !string.IsNullOrWhiteSpace(d.IpAddress))
            .ToDictionary(d => d.IpAddress, d => d, StringComparer.OrdinalIgnoreCase);

        var currentDevices = result.Devices
            .Where(d => !string.IsNullOrWhiteSpace(d.IpAddress))
            .ToDictionary(d => d.IpAddress, d => d, StringComparer.OrdinalIgnoreCase);

        foreach (var previousDevice in previousDevices.Values)
        {
            if (!currentDevices.ContainsKey(previousDevice.IpAddress))
            {
                if (_history.TryGetValue(previousDevice.IpAddress, out var entry))
                {
                    entry.Status = "Offline";
                    entry.LastLeftAt = DateTime.Now;
                    entry.Events.Add(new DeviceHistoryEvent
                    {
                        EventType = DeviceHistoryEventType.Left,
                        Timestamp = DateTime.Now,
                        Status = "Offline"
                    });

                    var watched = _watchedDevices.FirstOrDefault(w => 
                        w.IpAddress.Equals(previousDevice.IpAddress, StringComparison.OrdinalIgnoreCase) ||
                        w.MacAddress.Equals(previousDevice.MacAddress, StringComparison.OrdinalIgnoreCase));
                    
                    if (watched != null && watched.NotifyOnLeave)
                    {
                        ShowDeviceNotification($"{watched.Name} saiu da rede", $"{previousDevice.DisplayName} ({previousDevice.IpAddress})");
                    }
                }
            }
        }

        _lastDevices = result.Devices;

        foreach (var device in result.Devices)
        {
            var seenText = "agora";
            if (_history.TryGetValue(device.IpAddress, out var historyEntry))
            {
                var delta = DateTime.Now - historyEntry.SeenAt;
                seenText = delta.TotalMinutes < 1 ? "agora" : $"{(int)delta.TotalMinutes} min";
            }

            var osText = string.IsNullOrEmpty(device.OperatingSystem) ? "—" : $"{device.OperatingSystem} ({device.OSConfidence})";
            var servicesText = device.Services.Count > 0 ? $"{device.Services.Count}" : "—";
            var exploited = device.Vulnerabilities.Count(v => v.IsKnownExploited);
            var vulnsText = device.Vulnerabilities.Count == 0 ? "—"
                : exploited > 0 ? $"{device.Vulnerabilities.Count} ({exploited} KEV)"
                : $"{device.Vulnerabilities.Count}";

            var idx = _grid.Rows.Add(
                device.IpAddress,
                device.MacAddress,
                string.IsNullOrEmpty(device.Hostname) ? "—" : device.Hostname,
                device.Vendor,
                osText,
                device.DeviceType,
                device.Status,
                seenText,
                string.IsNullOrEmpty(device.OpenPorts) ? "—" : device.OpenPorts,
                servicesText,
                vulnsText,
                device.IsLocalDevice ? "✓ Sim" : "—"
            );
            _grid.Rows[idx].Tag = device;

            if (_history.TryGetValue(device.IpAddress, out var existing))
            {
                existing.Status = device.Status;
                existing.SeenAt = DateTime.Now;
                existing.MacAddress = device.MacAddress;
                existing.Hostname = device.Hostname;
                existing.Vendor = device.Vendor;
                existing.DeviceType = device.DeviceType;

                var wasVisibleBefore = previousDevices.ContainsKey(device.IpAddress);
                var lastEvent = existing.Events.LastOrDefault();
                if (!wasVisibleBefore || lastEvent?.EventType == DeviceHistoryEventType.Left)
                {
                    existing.Events.Add(new DeviceHistoryEvent
                    {
                        EventType = DeviceHistoryEventType.Seen,
                        Timestamp = DateTime.Now,
                        Status = device.Status
                    });

                    var watched = _watchedDevices.FirstOrDefault(w => 
                        w.IpAddress.Equals(device.IpAddress, StringComparison.OrdinalIgnoreCase) ||
                        w.MacAddress.Equals(device.MacAddress, StringComparison.OrdinalIgnoreCase));
                    
                    if (watched != null && watched.NotifyOnEnter)
                    {
                        ShowDeviceNotification($"{watched.Name} entrou na rede", $"{device.DisplayName} ({device.IpAddress})");
                    }
                }
            }
            else
            {
                var newHistoryEntry = new DeviceHistoryEntry
                {
                    IpAddress = device.IpAddress,
                    MacAddress = device.MacAddress,
                    Hostname = device.Hostname,
                    Vendor = device.Vendor,
                    DeviceType = device.DeviceType,
                    Status = device.Status,
                    SeenAt = DateTime.Now
                };

                newHistoryEntry.Events.Add(new DeviceHistoryEvent
                {
                    EventType = DeviceHistoryEventType.Seen,
                    Timestamp = DateTime.Now,
                    Status = device.Status
                });

                _history[device.IpAddress] = newHistoryEntry;
            }
        }

        if (_showOfflineCheck.Checked)
        {
            foreach (var historyEntry in _history.Values.Where(h => h.Status == "Offline"))
            {
                if (currentDevices.ContainsKey(historyEntry.IpAddress))
                    continue;

                var lastSeenText = "desconhecido";
                if (historyEntry.LastLeftAt.HasValue)
                {
                    var delta = DateTime.Now - historyEntry.LastLeftAt.Value;
                    if (delta.TotalMinutes < 60)
                        lastSeenText = $"{(int)delta.TotalMinutes} min atrás";
                    else if (delta.TotalHours < 24)
                        lastSeenText = $"{(int)delta.TotalHours} h atrás";
                    else
                        lastSeenText = $"{(int)delta.TotalDays} d atrás";
                }

                var idx = _grid.Rows.Add(
                    historyEntry.IpAddress,
                    historyEntry.MacAddress,
                    string.IsNullOrEmpty(historyEntry.Hostname) ? "—" : historyEntry.Hostname,
                    historyEntry.Vendor,
                    "—",
                    historyEntry.DeviceType,
                    "Offline",
                    lastSeenText,
                    "—",
                    "—",
                    "—",
                    "—"
                );
                _grid.Rows[idx].Tag = new DeviceInfo
                {
                    IpAddress = historyEntry.IpAddress,
                    MacAddress = historyEntry.MacAddress,
                    Hostname = historyEntry.Hostname,
                    Vendor = historyEntry.Vendor,
                    DeviceType = historyEntry.DeviceType,
                    Status = "Offline",
                    IsLocalDevice = false,
                    OperatingSystem = "",
                    OSConfidence = "",
                    Services = [],
                    Vulnerabilities = []
                };
            }
        }

        _deviceCountLabel.Text = _grid.Rows.Count > 0 ? $"{_grid.Rows.Count} dispositivos" : "Sem dispositivos";
        _summaryLabel.Text = $"{result.Devices.Count} online · {_grid.Rows.Count - result.Devices.Count} offline · Método: {result.ScanMethod}";
        ApplyFilter();
        SaveHistoryToDisk();
    }

    private void RefreshGrid()
    {
        if (_lastDevices.Count == 0)
            return;

        var result = new ScanResult
        {
            Devices = _lastDevices,
            ScanMethod = "Histórico",
            Duration = TimeSpan.Zero
        };
        DisplayDevices(result);
    }

    private void Grid_CellDoubleClick(object? sender, DataGridViewCellEventArgs e)
    {
        if (e.RowIndex < 0) return;
        if (_grid.Rows[e.RowIndex].Tag is not DeviceInfo device) return;
        if (!_history.TryGetValue(device.IpAddress, out var historyEntry)) return;

        using var historyForm = new Form
        {
            Text = $"Histórico · {device.DisplayName}",
            Size = new Size(480, 360),
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = false
        };

        var listBox = new ListBox
        {
            Dock = DockStyle.Fill,
            Font = Theme.BodyFont,
            BorderStyle = BorderStyle.FixedSingle
        };

        if (historyEntry.Events.Count == 0)
        {
            listBox.Items.Add("Sem eventos registados ainda.");
        }
        else
        {
            foreach (var historyEvent in historyEntry.Events.OrderByDescending(x => x.Timestamp))
            {
                var label = historyEvent.EventType == DeviceHistoryEventType.Seen
                    ? $"Visto às {historyEvent.Timestamp:dd/MM HH:mm:ss} · {historyEvent.Status}"
                    : $"Saiu às {historyEvent.Timestamp:dd/MM HH:mm:ss} · {historyEvent.Status}";
                listBox.Items.Add(label);
            }
        }

        historyForm.Controls.Add(listBox);
        historyForm.ShowDialog(this);
    }

    private void DetectNewDevices(List<DeviceInfo> devices)
    {
        if (_knownDevices.Count == 0)
        {
            _knownDevices = devices.Select(d => d.IpAddress).ToHashSet();
            return;
        }

        var newDevices = devices
            .Where(d => !_knownDevices.Contains(d.IpAddress))
            .ToList();

        if (newDevices.Count > 0)
        {
            var names = string.Join("\n", newDevices.Select(d => $"• {d.IpAddress} ({d.DisplayName})"));
            NotifyIcon? tray = null;

            try
            {
                tray = new NotifyIcon
                {
                    Visible = true,
                    Icon = SystemIcons.Information,
                    BalloonTipTitle = "Novo dispositivo na rede!",
                    BalloonTipText = $"{newDevices.Count} novo(s) dispositivo(s) detetado(s)",
                    BalloonTipIcon = ToolTipIcon.Info
                };
                tray.ShowBalloonTip(3000);
            }
            finally
            {
                if (tray != null)
                {
                    tray.Visible = false;
                    tray.Dispose();
                }
            }

            if (WindowState != FormWindowState.Minimized)
            {
                MessageBox.Show(
                    $"Novos dispositivos encontrados:\n\n{names}",
                    "Alerta de Rede",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        }

        _knownDevices = devices.Select(d => d.IpAddress).ToHashSet();
    }

    private void ExportButton_Click(object? sender, EventArgs e)
    {
        if (_lastDevices.Count == 0) return;

        using var dialog = new SaveFileDialog
        {
            Filter = "CSV (*.csv)|*.csv",
            FileName = $"dispositivos_rede_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
            Title = "Exportar dispositivos"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            try
            {
                ExportService.ExportToCsv(_lastDevices, dialog.FileName);
                _statusLabel.Text = $"Exportado para {Path.GetFileName(dialog.FileName)}";
                _statusLabel.ForeColor = Theme.Success;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erro ao exportar: {ex.Message}", "Erro",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        SaveHistoryToDisk();
        SaveWatchlist();
        _scanCts?.Cancel();
        _refreshTimer.Stop();
        _refreshTimer.Dispose();
        base.OnFormClosing(e);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        _ = RunScanAsync();
    }

    private void ShowDeviceNotification(string title, string message)
    {
        NotifyIcon? tray = null;

        try
        {
            tray = new NotifyIcon
            {
                Visible = true,
                Icon = SystemIcons.Information,
                BalloonTipTitle = title,
                BalloonTipText = message,
                BalloonTipIcon = ToolTipIcon.Info
            };
            tray.ShowBalloonTip(5000);
        }
        finally
        {
            if (tray != null)
            {
                tray.Visible = false;
                tray.Dispose();
            }
        }

        if (WindowState != FormWindowState.Minimized)
        {
            MessageBox.Show(
                $"{title}\n\n{message}",
                "Alerta de Dispositivo",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
    }

    private void WatchlistButton_Click(object? sender, EventArgs e)
    {
        using var form = new Form
        {
            Text = "Lista de Monitorização",
            Size = new Size(600, 450),
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = false
        };

        var list = new ListBox
        {
            Dock = DockStyle.Fill,
            Font = Theme.BodyFont,
            BorderStyle = BorderStyle.FixedSingle,
            Margin = new Padding(10)
        };

        RefreshWatchlist(list);

        var buttonPanel = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 60,
            Padding = new Padding(10)
        };

        var addButton = new Button
        {
            Text = "+ Adicionar Dispositivo",
            Size = new Size(160, 40),
            Location = new Point(10, 10)
        };
        Theme.StyleButton(addButton);
        addButton.Click += (_, _) => AddToWatchlist(list);

        var removeButton = new Button
        {
            Text = "- Remover Selecionado",
            Size = new Size(160, 40),
            Location = new Point(180, 10)
        };
        Theme.StyleButton(removeButton);
        removeButton.Click += (_, _) => RemoveFromWatchlist(list);

        buttonPanel.Controls.AddRange([addButton, removeButton]);
        form.Controls.AddRange([list, buttonPanel]);
        form.ShowDialog(this);
    }

    private void RefreshWatchlist(ListBox list)
    {
        list.Items.Clear();
        foreach (var watched in _watchedDevices)
        {
            var enterStatus = watched.NotifyOnEnter ? "✓" : "✗";
            var leaveStatus = watched.NotifyOnLeave ? "✓" : "✗";
            var status = $"[{enterStatus} Entrada] [{leaveStatus} Saída]";
            list.Items.Add($"{watched.Name} ({watched.IpAddress}) {status}");
        }
    }

    private void AddToWatchlist(ListBox list)
    {
        if (_grid.CurrentRow?.Tag is not DeviceInfo device)
        {
            MessageBox.Show("Seleciona um dispositivo da lista principal primeiro.", "Aviso",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var existing = _watchedDevices.FirstOrDefault(w =>
            w.IpAddress.Equals(device.IpAddress, StringComparison.OrdinalIgnoreCase) ||
            w.MacAddress.Equals(device.MacAddress, StringComparison.OrdinalIgnoreCase));

        if (existing != null)
        {
            MessageBox.Show("Este dispositivo já está na lista de monitorização.", "Aviso",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        using var form = new Form
        {
            Text = "Adicionar à Monitorização",
            Size = new Size(400, 250),
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = false
        };

        var nameLabel = new Label
        {
            Text = "Nome:",
            Location = new Point(20, 20),
            AutoSize = true
        };

        var nameBox = new TextBox
        {
            Text = device.DisplayName,
            Location = new Point(20, 45),
            Size = new Size(340, 26)
        };

        var enterCheck = new CheckBox
        {
            Text = "Notificar quando entrar",
            Location = new Point(20, 85),
            Checked = true,
            AutoSize = true
        };

        var leaveCheck = new CheckBox
        {
            Text = "Notificar quando sair",
            Location = new Point(20, 115),
            Checked = true,
            AutoSize = true
        };

        var okButton = new Button
        {
            Text = "Adicionar",
            Size = new Size(100, 35),
            Location = new Point(20, 160),
            DialogResult = DialogResult.OK
        };
        Theme.StyleButton(okButton);

        var cancelButton = new Button
        {
            Text = "Cancelar",
            Size = new Size(100, 35),
            Location = new Point(140, 160),
            DialogResult = DialogResult.Cancel
        };
        Theme.StyleButton(cancelButton);

        form.Controls.AddRange([nameLabel, nameBox, enterCheck, leaveCheck, okButton, cancelButton]);

        if (form.ShowDialog(this) == DialogResult.OK)
        {
            var watched = new WatchedDevice
            {
                IpAddress = device.IpAddress,
                MacAddress = device.MacAddress,
                Name = nameBox.Text.Trim(),
                NotifyOnEnter = enterCheck.Checked,
                NotifyOnLeave = leaveCheck.Checked,
                AddedAt = DateTime.Now
            };

            _watchedDevices.Add(watched);
            SaveWatchlist();
            RefreshWatchlist(list);
        }
    }

    private void RemoveFromWatchlist(ListBox list)
    {
        if (list.SelectedIndex < 0)
        {
            MessageBox.Show("Seleciona um dispositivo da lista de monitorização.", "Aviso",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _watchedDevices.RemoveAt(list.SelectedIndex);
        SaveWatchlist();
        RefreshWatchlist(list);
    }

    private void ShowDetailsButton_Click(object? sender, EventArgs e)
    {
        if (_grid.CurrentRow?.Tag is not DeviceInfo device)
        {
            MessageBox.Show("Seleciona um dispositivo da lista primeiro.", "Aviso",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        using var form = new Form
        {
            Text = $"Detalhes: {device.DisplayName}",
            Size = new Size(760, 620),
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = true,
            BackColor = Theme.Background,
            ForeColor = Theme.Text
        };

        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(20),
            AutoScroll = true,
            BackColor = Theme.Background
        };

        var y = 10;

        // Basic Info
        AddLabel(panel, "Informação Básica", ref y, true);
        AddLabel(panel, $"IP: {device.IpAddress}", ref y);
        AddLabel(panel, $"MAC: {device.MacAddress}", ref y);
        AddLabel(panel, $"Hostname: {device.Hostname ?? "—"}", ref y);
        AddLabel(panel, $"Fabricante: {device.Vendor}", ref y);
        AddLabel(panel, $"Tipo: {device.DeviceType}", ref y);
        AddLabel(panel, $"Estado: {device.Status}", ref y);
        AddLabel(panel, $"Visto há: {(DateTime.Now - device.LastSeen).TotalMinutes:F0} minutos", ref y);
        y += 10;

        // OS Info
        if (!string.IsNullOrEmpty(device.OperatingSystem))
        {
            AddLabel(panel, "Sistema Operacional", ref y, true);
            AddLabel(panel, $"OS: {device.OperatingSystem}", ref y);
            AddLabel(panel, $"Confiança: {device.OSConfidence}", ref y);
            y += 10;
        }

        AddServiceAndVulnerabilitySections(panel, device, ref y);

        form.Controls.Add(panel);
        form.ShowDialog(this);
    }

    private void AddLabel(Panel panel, string text, ref int y, bool isHeader = false)
    {
        var label = new Label
        {
            Text = text,
            Location = new Point(20, y),
            AutoSize = true,
            Font = isHeader ? new Font("Segoe UI", 10F, FontStyle.Bold) : new Font("Segoe UI", 9F),
            ForeColor = isHeader ? Theme.Primary : Theme.Text
        };
        panel.Controls.Add(label);
        y += isHeader ? 25 : 20;
    }

    /// <summary>Texto com quebra de linha automática (largura ajustada à janela de detalhes de 760 px).</summary>
    private static void AddWrappedLabel(Panel panel, string text, ref int y, int x, Font font, Color color)
    {
        var width = 690 - x;
        var label = new Label
        {
            Text = text,
            Location = new Point(x, y),
            AutoSize = true,
            MaximumSize = new Size(width, 0),
            Font = font,
            ForeColor = color
        };
        panel.Controls.Add(label);
        y += label.PreferredHeight + 4;
    }

    private static string DescribeCheck(ServiceInfo service) => service.VulnerabilityCheck switch
    {
        VulnerabilityCheckStatus.Checked => "verificado na NVD",
        VulnerabilityCheckStatus.CheckedWithStaleData => "verificado com dados em cache (sem ligação)",
        VulnerabilityCheckStatus.VersionUnknown => "versão desconhecida, não é possível verificar",
        VulnerabilityCheckStatus.UnsupportedProduct => "produto ainda não suportado",
        VulnerabilityCheckStatus.SourceUnavailable => "NVD inacessível, não verificado",
        _ => ""
    };

    private static Color SeverityColor(string severity) => severity switch
    {
        "Critical" => Color.FromArgb(255, 82, 82),
        "High" => Color.FromArgb(255, 140, 66),
        "Medium" => Theme.Warning,
        "Low" => Theme.Success,
        _ => Theme.TextMuted
    };

    private static string SeverityLabel(string severity) => severity switch
    {
        "Critical" => "Crítica",
        "High" => "Alta",
        "Medium" => "Média",
        "Low" => "Baixa",
        "None" => "Nenhuma",
        _ => "Sem pontuação"
    };

    private void AddServiceAndVulnerabilitySections(Panel panel, DeviceInfo device, ref int y)
    {
        var small = new Font("Segoe UI", 8.5F);
        var smallItalic = new Font("Segoe UI", 8F, FontStyle.Italic);
        var bold = new Font("Segoe UI", 9F, FontStyle.Bold);

        // Serviços
        AddLabel(panel, "Serviços", ref y, true);
        if (device.Services.Count == 0)
        {
            AddLabel(panel, "Nenhum serviço detetado", ref y);
        }
        foreach (var service in device.Services)
        {
            var product = string.Join(" ", new[] { service.Product, service.Version }.Where(s => !string.IsNullOrWhiteSpace(s)));
            var line = $"Porta {service.Port}: {service.Service}" + (product.Length > 0 ? $" · {product}" : "");
            if (service.IsDistroPackage)
                line += $" ({service.DistroName})";
            AddLabel(panel, line, ref y);

            var check = DescribeCheck(service);
            if (check.Length > 0)
                AddWrappedLabel(panel, $"Vulnerabilidades: {check}", ref y, 40, smallItalic, Theme.TextMuted);

            if (!string.IsNullOrEmpty(service.Banner))
            {
                var banner = new string(service.Banner.Take(100).Select(c => char.IsControl(c) ? ' ' : c).ToArray()).Trim();
                AddWrappedLabel(panel, $"Banner: {banner}", ref y, 40, smallItalic, Theme.TextMuted);
            }
        }
        y += 10;

        // Vulnerabilidades
        AddLabel(panel, "Vulnerabilidades potenciais", ref y, true);

        var requested = device.Services.Any(s => s.VulnerabilityCheck != VulnerabilityCheckStatus.NotRequested);
        if (!requested)
        {
            AddLabel(panel, "Verificação não pedida (ativa \"Serviços\" e \"Vulnerabilidades\").", ref y);
            return;
        }

        if (device.Vulnerabilities.Count == 0)
        {
            var anyChecked = device.Services.Any(s => s.VulnerabilityCheck is VulnerabilityCheckStatus.Checked or VulnerabilityCheckStatus.CheckedWithStaleData);
            AddLabel(panel, anyChecked
                ? "Nenhuma vulnerabilidade conhecida para as versões detetadas."
                : "Nenhum serviço pôde ser verificado (ver estado de cada serviço acima).", ref y);
            return;
        }

        AddWrappedLabel(panel,
            "Correspondência pela versão anunciada no banner. Não confirma que o dispositivo está vulnerável: " +
            "configuração, módulos ativos e correções aplicadas pelo fabricante podem mudar o resultado.",
            ref y, 20, smallItalic, Theme.TextMuted);

        if (device.Vulnerabilities.Any(v => v.MayBeBackported))
        {
            AddWrappedLabel(panel,
                "⚠ Pacotes de distribuição (Ubuntu, Debian, RHEL…) recebem correções sem mudar o número de versão. " +
                "Confirma no próprio sistema se estas falhas já foram corrigidas.",
                ref y, 20, small, Theme.Warning);
        }
        y += 6;

        foreach (var vuln in device.Vulnerabilities)
        {
            var score = vuln.CvssScore.HasValue ? $" {vuln.CvssScore:0.0}" : "";
            var header = $"[{SeverityLabel(vuln.Severity)}{score}] {vuln.CVE} · {vuln.Product} {vuln.DetectedVersion} (porta {vuln.Port})";
            AddWrappedLabel(panel, header, ref y, 20, bold, SeverityColor(vuln.Severity));

            if (vuln.IsKnownExploited)
            {
                var kev = "🔥 Exploração ativa confirmada (CISA KEV)" + (vuln.KnownRansomwareUse ? " · usada em ransomware" : "");
                AddWrappedLabel(panel, kev, ref y, 40, bold, Theme.Danger);
            }

            if (!string.IsNullOrWhiteSpace(vuln.Description))
            {
                var description = vuln.Description.Length > 400 ? vuln.Description[..400] + "…" : vuln.Description;
                AddWrappedLabel(panel, description, ref y, 40, small, Theme.Text);
            }

            var link = new LinkLabel
            {
                Text = vuln.Url,
                Location = new Point(40, y),
                AutoSize = true,
                Font = small,
                LinkColor = Theme.Primary,
                ActiveLinkColor = Theme.PrimaryHover
            };
            var url = vuln.Url;
            link.LinkClicked += (_, _) =>
            {
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); }
                catch { /* sem browser predefinido */ }
            };
            panel.Controls.Add(link);
            y += 24;
        }

        if (!string.IsNullOrEmpty(_lastVulnerabilityNote))
        {
            y += 6;
            AddWrappedLabel(panel, _lastVulnerabilityNote, ref y, 20, smallItalic, Theme.TextMuted);
        }
    }

    private void AuditReportButton_Click(object? sender, EventArgs e)
    {
        if (_lastDevices.Count == 0)
        {
            MessageBox.Show("Executa um scan primeiro para gerar um relatório.", "Aviso",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        using var form = new Form
        {
            Text = "Gerar Relatório de Auditoria",
            Size = new Size(450, 350),
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = false
        };

        var formatLabel = new Label
        {
            Text = "Formato:",
            Location = new Point(20, 20),
            AutoSize = true
        };

        var formatCombo = new ComboBox
        {
            Location = new Point(20, 45),
            Size = new Size(200, 26),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        formatCombo.Items.AddRange(["HTML", "JSON", "Markdown"]);
        formatCombo.SelectedIndex = 0;

        var auditorLabel = new Label
        {
            Text = "Auditor (opcional):",
            Location = new Point(20, 85),
            AutoSize = true
        };

        var auditorBox = new TextBox
        {
            Location = new Point(20, 110),
            Size = new Size(380, 26)
        };

        var notesLabel = new Label
        {
            Text = "Notas (opcional):",
            Location = new Point(20, 145),
            AutoSize = true
        };

        var notesBox = new TextBox
        {
            Location = new Point(20, 170),
            Size = new Size(380, 60),
            Multiline = true
        };

        var includeVulnsCheck = new CheckBox
        {
            Text = "Incluir vulnerabilidades",
            Location = new Point(20, 240),
            Checked = true,
            AutoSize = true
        };

        var includeServicesCheck = new CheckBox
        {
            Text = "Incluir detalhes de serviços",
            Location = new Point(20, 265),
            Checked = true,
            AutoSize = true
        };

        var generateButton = new Button
        {
            Text = "Gerar Relatório",
            Size = new Size(120, 35),
            Location = new Point(20, 290),
            DialogResult = DialogResult.OK
        };
        Theme.StyleButton(generateButton);

        var cancelButton = new Button
        {
            Text = "Cancelar",
            Size = new Size(100, 35),
            Location = new Point(150, 290),
            DialogResult = DialogResult.Cancel
        };
        Theme.StyleButton(cancelButton);

        form.Controls.AddRange([formatLabel, formatCombo, auditorLabel, auditorBox, notesLabel, notesBox, includeVulnsCheck, includeServicesCheck, generateButton, cancelButton]);

        if (form.ShowDialog(this) == DialogResult.OK)
        {
            var options = new AuditReportService.AuditReportOptions
            {
                IncludeVulnerabilities = includeVulnsCheck.Checked,
                IncludeServices = includeServicesCheck.Checked,
                IncludeOSInfo = true,
                IncludeHistory = true,
                AuditorName = auditorBox.Text.Trim(),
                Notes = notesBox.Text.Trim()
            };

            var format = formatCombo.SelectedItem.ToString();
            var extension = format?.ToLower() switch
            {
                "html" => "html",
                "json" => "json",
                "markdown" => "md",
                _ => "html"
            };

            using var dialog = new SaveFileDialog
            {
                Filter = $"{format} (*.{extension})|*.{extension}",
                FileName = $"auditoria_rede_{DateTime.Now:yyyyMMdd_HHmmss}.{extension}",
                Title = "Guardar Relatório"
            };

            if (dialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    var result = new ScanResult
                    {
                        Devices = _lastDevices,
                        ScanMethod = "Auditoria Completa",
                        Duration = TimeSpan.Zero,
                        VulnerabilitySourceNote = _lastVulnerabilityNote
                    };

                    var report = format switch
                    {
                        "HTML" => AuditReportService.GenerateHTMLReportAsync(result, _history, options).Result,
                        "JSON" => AuditReportService.GenerateJSONReportAsync(result, _history, options).Result,
                        "Markdown" => AuditReportService.GenerateMarkdownReportAsync(result, _history, options).Result,
                        _ => ""
                    };

                    File.WriteAllText(dialog.FileName, report);
                    _statusLabel.Text = $"Relatório guardado em {Path.GetFileName(dialog.FileName)}";
                    _statusLabel.ForeColor = Theme.Success;

                    // Ask if user wants to open the report
                    if (MessageBox.Show("Relatório gerado com sucesso! Abrir agora?", "Sucesso",
                        MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    {
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = dialog.FileName,
                            UseShellExecute = true
                        });
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Erro ao gerar relatório: {ex.Message}", "Erro",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}
