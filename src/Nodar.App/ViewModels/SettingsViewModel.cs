using CommunityToolkit.Mvvm.ComponentModel;
using Nodar.App.Services;
using Nodar.Core.Localization;
using Nodar.Core.Settings;
using static Nodar.Core.Localization.Loc;

namespace Nodar.App.ViewModels;

/// <summary>
/// As preferências do utilizador (opções de scan, atualização automática, segundo plano, idioma).
/// Grava-as sempre que mudam. O que depende de outras partes da app é anunciado por eventos.
/// </summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly AppSettings _settings;
    private bool _loading;

    /// <summary>"Mostrar offline" mudou: a lista de dispositivos tem de ser refeita.</summary>
    public event Action? ShowOfflineChanged;

    /// <summary>A atualização automática ou o seu intervalo mudou: o temporizador tem de ser reconfigurado.</summary>
    public event Action? RefreshScheduleChanged;

    /// <summary>O Windows recusou o registo de "iniciar com o Windows" (a opção foi desfeita).</summary>
    public event Action? StartupRegistrationFailed;

    public SettingsViewModel(AppSettings settings)
    {
        _settings = settings;

        _loading = true;
        DeepScan = settings.DeepScan;
        PortScan = settings.PortScan;
        OsDetection = settings.OsDetection;
        ServiceDetection = settings.ServiceDetection;
        VulnerabilityScan = settings.VulnerabilityScan;
        AutoRefresh = settings.AutoRefresh;
        ShowOffline = settings.ShowOffline;
        WindowsNotifications = settings.WindowsNotifications;
        CloseToTray = settings.CloseToTray;
        StartWithWindows = settings.StartWithWindows;
        SelectedLanguage = LanguageOptions.FirstOrDefault(o => o.Code == settings.Language) ?? LanguageOptions[0];
        StartupRegistration.Refresh(settings.StartWithWindows);
        SelectedInterval = IntervalOptions.FirstOrDefault(o => o.Seconds == settings.RefreshIntervalSeconds) ?? IntervalOptions[1];
        _loading = false;
    }

    // ================================================================ Opções de scan

    [ObservableProperty] private bool _deepScan;
    [ObservableProperty] private bool _portScan;
    [ObservableProperty] private bool _osDetection;
    [ObservableProperty] private bool _serviceDetection;
    [ObservableProperty] private bool _vulnerabilityScan;

    // Dependências: vulnerabilidades ⇒ serviços ⇒ portas.
    partial void OnVulnerabilityScanChanged(bool value)
    {
        if (value) { ServiceDetection = true; }
        Save();
    }

    partial void OnServiceDetectionChanged(bool value)
    {
        if (value) PortScan = true;
        else VulnerabilityScan = false;
        Save();
    }

    partial void OnPortScanChanged(bool value)
    {
        if (!value) ServiceDetection = false;
        Save();
    }

    partial void OnDeepScanChanged(bool value) => Save();
    partial void OnOsDetectionChanged(bool value) => Save();

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

    // ================================================================ Atualização automática e lista

    [ObservableProperty] private bool _autoRefresh;
    [ObservableProperty] private bool _showOffline;
    [ObservableProperty] private IntervalOption? _selectedInterval;

    public IReadOnlyList<IntervalOption> IntervalOptions { get; } = [new(60), new(120), new(300), new(900)];

    /// <summary>Intervalo entre scans automáticos (2 minutos se nada estiver escolhido).</summary>
    public TimeSpan RefreshInterval => TimeSpan.FromSeconds(SelectedInterval?.Seconds ?? 120);

    partial void OnAutoRefreshChanged(bool value)
    {
        Save();
        RefreshScheduleChanged?.Invoke();
    }

    partial void OnSelectedIntervalChanged(IntervalOption? value)
    {
        Save();
        RefreshScheduleChanged?.Invoke();
    }

    partial void OnShowOfflineChanged(bool value)
    {
        Save();
        ShowOfflineChanged?.Invoke();
    }

    // ================================================================ Segundo plano e notificações do Windows

    [ObservableProperty] private bool _windowsNotifications;
    [ObservableProperty] private bool _closeToTray;
    [ObservableProperty] private bool _startWithWindows;

    /// <summary>Iniciar com o Windows só é possível a partir do executável publicado (Nodar.exe).</summary>
    public bool CanStartWithWindows => StartupRegistration.CurrentCommand() != null;

    partial void OnWindowsNotificationsChanged(bool value) => Save();
    partial void OnCloseToTrayChanged(bool value) => Save();

    partial void OnStartWithWindowsChanged(bool value)
    {
        if (_loading)
            return;
        if (!StartupRegistration.Set(value) && value)
        {
            StartupRegistrationFailed?.Invoke();
            _loading = true;
            StartWithWindows = false;
            _loading = false;
        }
        Save();
    }

    /// <summary>Já se explicou ao utilizador que a app continua na bandeja?</summary>
    public bool TrayHintShown => _settings.TrayHintShown;

    public void MarkTrayHintShown()
    {
        _settings.TrayHintShown = true;
        _settings.Save();
    }

    // ================================================================ Idioma

    /// <summary>Opções fixas (nunca recriadas): ver <see cref="MainViewModel"/> e <see cref="RefreshLabels"/>.</summary>
    public IReadOnlyList<LanguageOption> LanguageOptions { get; } = [new("auto"), new("pt"), new("en")];

    [ObservableProperty] private LanguageOption? _selectedLanguage;

    partial void OnSelectedLanguageChanged(LanguageOption? value)
    {
        // A caixa de seleção pode limpar a seleção por momentos: isso não é "escolher automático".
        if (value == null)
            return;
        Instance.Apply(value.Code);
        Save();
    }

    /// <summary>
    /// O idioma mudou: atualiza só os textos das opções. As listas nunca são recriadas (isso limpava a
    /// seleção e provocava um ciclo pt↔en que bloqueava a app).
    /// </summary>
    public void RefreshLabels()
    {
        foreach (var option in LanguageOptions)
            option.Refresh();
        foreach (var option in IntervalOptions)
            option.Refresh();
    }

    // ================================================================ Gravação

    private void Save()
    {
        if (_loading)
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
