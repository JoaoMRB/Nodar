using Avalonia.Data.Converters;

namespace Nodar.App.ViewModels;

public static class Converters
{
    /// <summary>Dispositivos offline ficam esbatidos.</summary>
    public static readonly IValueConverter OnlineOpacity =
        new FuncValueConverter<bool, double>(online => online ? 1.0 : 0.45);

    public static readonly IValueConverter IsPositive =
        new FuncValueConverter<int, bool>(n => n > 0);
}
