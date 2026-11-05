using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using static Nodar.Core.Localization.Loc;

namespace Nodar.App.ViewModels;

/// <summary>
/// Filtros da lista de dispositivos: por grupo de tipo (computadores, telemóveis, TV…) e por estado
/// (com vulnerabilidades, monitorizados, novos, offline).
/// </summary>
public static class DeviceFilters
{
    public const string All = "all";

    // Grupos de tipo, pela ordem em que aparecem.
    public static readonly string[] TypeGroups =
        ["computers", "phones", "tv", "network", "printers", "smarthome", "cameras", "consoles", "servers", "other"];

    // Filtros por estado (aparecem depois dos tipos, só quando há algum dispositivo nessa situação).
    public static readonly string[] StateFilters = ["vulnerable", "watched", "new", "offline"];

    /// <summary>Grupo de um dispositivo a partir do tipo guardado no Core.</summary>
    public static string GroupOf(string deviceType, bool isGateway, bool isLocal)
    {
        if (isGateway) return "network";
        if (isLocal) return "computers";
        return deviceType switch
        {
            "Computador" => "computers",
            "Telemóvel" or "Apple" => "phones",
            "TV" => "tv",
            "Router" => "network",
            "Impressora" => "printers",
            "Smart Home" => "smarthome",
            "Câmara" => "cameras",
            "Consola" => "consoles",
            "Servidor" or "Virtual" => "servers",
            _ => "other"
        };
    }

    public static bool Matches(DeviceItemViewModel device, string filter) => filter switch
    {
        All or "" => true,
        "vulnerable" => device.HasVulnerabilities,
        "watched" => device.IsWatched,
        "new" => device.IsNew,
        "offline" => !device.IsOnline,
        _ => device.Group == filter
    };

    public static string IconKey(string filter) => filter switch
    {
        "computers" => "Icon.Laptop",
        "phones" => "Icon.Phone",
        "tv" => "Icon.Tv",
        "network" => "Icon.Router",
        "printers" => "Icon.Printer",
        "smarthome" => "Icon.Home",
        "cameras" => "Icon.Camera",
        "consoles" => "Icon.Gamepad",
        "servers" => "Icon.Server",
        "vulnerable" => "Icon.Shield",
        "watched" => "Icon.Star",
        "new" => "Icon.Sparkle",
        "offline" => "Icon.Clock",
        "other" => "Icon.Chip",
        _ => "Icon.Grid"
    };
}

/// <summary>Uma "pílula" de filtro: ícone, nome, contagem e estado selecionado.</summary>
public sealed partial class FilterChipViewModel(string key, int count) : ObservableObject
{
    public string Key { get; } = key;

    [ObservableProperty] private int _count = count;
    [ObservableProperty] private bool _isSelected;

    public string Label => T("filter." + Key);
    public Geometry Icon => Visuals.Icon(DeviceFilters.IconKey(Key));
    public bool IsState => DeviceFilters.StateFilters.Contains(Key);

    public void Refresh() => OnPropertyChanged(nameof(Label));
}
