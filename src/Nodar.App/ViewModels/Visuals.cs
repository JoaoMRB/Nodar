using Avalonia;
using Avalonia.Media;

namespace Nodar.App.ViewModels;

/// <summary>Ícones, cores e textos derivados dos dados (usados pelos ViewModels).</summary>
public static class Visuals
{
    public static Geometry Icon(string key) =>
        Application.Current?.TryGetResource(key, null, out var value) == true && value is Geometry g
            ? g
            : Geometry.Parse("M12 12 h.01");

    private static IBrush Brush(string hex) => new SolidColorBrush(Color.Parse(hex));

    public sealed record DeviceStyle(string IconKey, IBrush Tint, IBrush Glyph);

    /// <summary>Ícone e cor por tipo de dispositivo (fundo suave + traço saturado).</summary>
    public static DeviceStyle ForType(string type, bool isGateway, bool isLocal)
    {
        if (isGateway) return new("Icon.Router", Brush("#267C6CFF"), Brush("#A79CFF"));
        if (isLocal) return new("Icon.Laptop", Brush("#264C8DFF"), Brush("#7FB0FF"));

        return type switch
        {
            "Router" => new("Icon.Router", Brush("#267C6CFF"), Brush("#A79CFF")),
            "Computador" => new("Icon.Computer", Brush("#264C8DFF"), Brush("#7FB0FF")),
            "Apple" => new("Icon.Phone", Brush("#26E5E7EB"), Brush("#E5E7EB")),
            "Telemóvel" => new("Icon.Phone", Brush("#2634D399"), Brush("#6EE7B7")),
            "TV" => new("Icon.Tv", Brush("#26F472B6"), Brush("#F9A8D4")),
            "Impressora" => new("Icon.Printer", Brush("#26FBBF24"), Brush("#FCD34D")),
            "Servidor" => new("Icon.Server", Brush("#2622D3EE"), Brush("#67E8F9")),
            "Smart Home" => new("Icon.Home", Brush("#26FB923C"), Brush("#FDBA74")),
            "Consola" => new("Icon.Gamepad", Brush("#26A78BFA"), Brush("#C4B5FD")),
            "Câmara" => new("Icon.Camera", Brush("#26F87171"), Brush("#FCA5A5")),
            "Virtual" => new("Icon.Cube", Brush("#2694A3B8"), Brush("#CBD5E1")),
            _ => new("Icon.Chip", Brush("#1AFFFFFF"), Brush("#A1A7B5"))
        };
    }

    public static IBrush SeverityBrush(string severity) => severity switch
    {
        "Critical" => Brush("#FF4D6D"),
        "High" => Brush("#FB923C"),
        "Medium" => Brush("#FBBF24"),
        "Low" => Brush("#34D399"),
        _ => Brush("#6B7180")
    };

    public static IBrush SeveritySoftBrush(string severity) => severity switch
    {
        "Critical" => Brush("#26FF4D6D"),
        "High" => Brush("#26FB923C"),
        "Medium" => Brush("#26FBBF24"),
        "Low" => Brush("#2634D399"),
        _ => Brush("#1AFFFFFF")
    };

    public static string SeverityLabel(string severity) => severity switch
    {
        "Critical" => "Crítica",
        "High" => "Alta",
        "Medium" => "Média",
        "Low" => "Baixa",
        "None" => "Nenhuma",
        _ => "Sem pontuação"
    };

    public static int SeverityRank(string severity) => severity switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0
    };

    public static readonly IBrush OnlineBrush = Brush("#34D399");
    public static readonly IBrush OfflineBrush = Brush("#6B7180");

    /// <summary>"agora", "há 5 min", "há 3 h", "há 2 d", "12/10/2026".</summary>
    public static string Relative(DateTime? when, DateTime? now = null)
    {
        if (when == null)
            return "—";
        var delta = (now ?? DateTime.Now) - when.Value;
        if (delta.TotalSeconds < 60) return "agora";
        if (delta.TotalMinutes < 60) return $"há {(int)delta.TotalMinutes} min";
        if (delta.TotalHours < 24) return $"há {(int)delta.TotalHours} h";
        if (delta.TotalDays < 30) return $"há {(int)delta.TotalDays} d";
        return when.Value.ToString("dd/MM/yyyy");
    }
}
