using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Text.Json;

namespace Nodar.Core.Localization;

/// <summary>
/// Traduções da app (interface, notificações, mensagens do scan e relatórios).
/// </summary>
/// <remarks>
/// <para>Os textos estão em <c>Localization/pt.json</c> e <c>Localization/en.json</c> (recursos embutidos).
/// Acrescentar um idioma = acrescentar um ficheiro com as mesmas chaves.</para>
/// <para>Mudar <see cref="Language"/> notifica <c>Item[]</c>: as ligações da interface (<c>{l:T Chave}</c>)
/// atualizam-se sem reiniciar.</para>
/// </remarks>
public sealed class Loc : INotifyPropertyChanged
{
    // Atenção à ordem: os campos estáticos inicializam-se por ordem de declaração, e o construtor usa Supported.
    public static readonly IReadOnlyList<string> Supported = ["pt", "en"];
    public const string Fallback = "en";

    public static Loc Instance { get; } = new();

    private readonly Dictionary<string, Dictionary<string, string>> _tables = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, string> _current;
    private string _language;

    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action? LanguageChanged;

    private Loc()
    {
        foreach (var lang in Supported)
            _tables[lang] = LoadTable(lang);
        _language = SystemLanguage();
        _current = _tables[_language];
    }

    /// <summary>Idioma do Windows se for suportado; senão inglês.</summary>
    public static string SystemLanguage()
    {
        var code = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName;
        return Supported.Contains(code) ? code : Fallback;
    }

    public string Language
    {
        get => _language;
        set
        {
            var lang = Supported.Contains(value) ? value : SystemLanguage();
            if (lang == _language)
                return;
            _language = lang;
            _current = _tables[lang];
            // Indexador: o WPF usa "Item[]", o Avalonia "Item"; null = "todas as propriedades mudaram".
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item"));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
            LanguageChanged?.Invoke();
        }
    }

    /// <summary>"auto" segue o Windows; "pt"/"en" fixam o idioma.</summary>
    public void Apply(string? preference) => Language = preference is "pt" or "en" ? preference : SystemLanguage();

    /// <summary>Texto para a chave no idioma atual (com recurso ao inglês e, por fim, à própria chave).</summary>
    public string this[string key] =>
        _current.TryGetValue(key, out var text) ? text
        : _tables[Fallback].TryGetValue(key, out var fallback) ? fallback
        : key;

    public static string T(string key) => Instance[key];

    /// <summary>Texto com parâmetros: "{0} dispositivos" → "17 dispositivos".</summary>
    public static string F(string key, params object?[] args) =>
        string.Format(Instance.Culture, Instance[key], args);

    /// <summary>Singular/plural: usa "<paramref name="key"/>.one" quando <paramref name="count"/> é 1.</summary>
    public static string Plural(string key, int count, params object?[] args)
    {
        var all = new object?[] { count }.Concat(args).ToArray();
        return F(count == 1 && Instance.Has(key + ".one") ? key + ".one" : key, all);
    }

    /// <summary>
    /// Tipo de dispositivo para mostrar. O Core guarda os tipos com valores estáveis (em português, como sempre
    /// estiveram no histórico) e só os traduz na apresentação: "Telemóvel" → "Phone".
    /// </summary>
    public static string DeviceType(string? type)
    {
        var key = "type." + (type ?? "").Replace(" ", "");
        return Instance.Has(key) ? Instance[key] : type ?? "";
    }

    public bool Has(string key) => _current.ContainsKey(key) || _tables[Fallback].ContainsKey(key);

    public CultureInfo Culture => _language == "pt" ? CultureInfo.GetCultureInfo("pt-PT") : CultureInfo.GetCultureInfo("en-GB");

    /// <summary>Chaves de um idioma (para testes).</summary>
    public IReadOnlyCollection<string> KeysOf(string language) => _tables[language].Keys;

    private static Dictionary<string, string> LoadTable(string lang)
    {
        var assembly = typeof(Loc).Assembly;
        var resource = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith($".Localization.{lang}.json", StringComparison.OrdinalIgnoreCase));
        if (resource == null)
            return new Dictionary<string, string>(StringComparer.Ordinal);

        using var stream = assembly.GetManifestResourceStream(resource)!;
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream) ?? [];
    }
}
