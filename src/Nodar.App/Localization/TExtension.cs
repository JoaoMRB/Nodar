using Avalonia.Data;
using Avalonia.Markup.Xaml;
using Nodar.Core.Localization;

namespace Nodar.App.Localization;

/// <summary>
/// Texto traduzido em XAML: <c>Text="{l:T devices.title}"</c>. A ligação acompanha mudanças de idioma.
/// </summary>
public sealed class TExtension(string key) : MarkupExtension
{
    public string Key { get; set; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]") { Source = Loc.Instance, Mode = BindingMode.OneWay };
}
