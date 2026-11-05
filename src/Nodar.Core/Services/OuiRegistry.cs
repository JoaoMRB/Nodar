using System.Text;
using System.Text.RegularExpressions;

namespace Nodar.Core.Services;

/// <summary>
/// Registo oficial de fabricantes por prefixo de MAC (IEEE MA-L, cerca de 40 000 entradas).
/// </summary>
/// <remarks>
/// Descarregado de <see cref="SourceUrl"/> (público, sem enviar nenhum dado do utilizador), guardado em
/// <c>%LOCALAPPDATA%\Nodar\cache\oui.tsv</c> e renovado a cada 30 dias. Enquanto não estiver disponível,
/// usa-se a pequena tabela embutida em <see cref="VendorService"/>.
/// </remarks>
public static class OuiRegistry
{
    public const string SourceUrl = "https://standards-oui.ieee.org/oui/oui.csv";
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(30);

    private static volatile Dictionary<string, string>? _table;
    private static Task? _loading;
    private static readonly object Sync = new();

    public static bool IsLoaded => _table != null;
    public static int Count => _table?.Count ?? 0;

    public static string CachePath =>
        Path.Combine(NodarPaths.CacheDirectory, "oui.tsv");

    /// <summary>Fabricante (nome curto) para um MAC, ou <c>null</c> se o registo não estiver carregado/não o conhecer.</summary>
    public static string? Lookup(string mac)
    {
        var table = _table;
        if (table == null)
            return null;
        var hex = new string((mac ?? "").Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        return hex.Length >= 6 && table.TryGetValue(hex[..6], out var name) ? name : null;
    }

    /// <summary>
    /// Carrega da cache ou descarrega. Pode ser chamado várias vezes: o trabalho só é feito uma vez.
    /// Espera no máximo <paramref name="wait"/>; se não terminar a tempo, continua em segundo plano.
    /// </summary>
    public static async Task EnsureLoadedAsync(TimeSpan wait, CancellationToken ct = default)
    {
        Task loading;
        lock (Sync)
            loading = _loading ??= Task.Run(LoadAsync);
        try
        {
            await loading.WaitAsync(wait, ct);
        }
        catch (TimeoutException)
        {
            // Continua em segundo plano; os próximos scans já o usam.
        }
    }

    private static async Task LoadAsync()
    {
        try
        {
            var cached = File.Exists(CachePath) ? new FileInfo(CachePath) : null;
            if (cached != null && DateTime.UtcNow - cached.LastWriteTimeUtc < MaxAge)
            {
                _table = ReadTsv(CachePath);
                if (_table.Count > 1000)
                    return;
            }

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Nodar/1.0");
                var csv = await http.GetStringAsync(SourceUrl);
                var table = ParseCsv(csv);
                if (table.Count > 1000)
                {
                    WriteTsv(CachePath, table);
                    _table = table;
                    return;
                }
            }
            catch
            {
                // Sem internet: usar cache antiga se houver.
            }

            if (cached != null)
                _table = ReadTsv(CachePath);
        }
        catch
        {
            // Registo opcional: fica a tabela embutida.
        }
        finally
        {
            if (_table == null)
                lock (Sync) _loading = null; // permitir nova tentativa no próximo scan
        }
    }

    // ================================================================ formato

    /// <summary>Lê o CSV do IEEE (Registry,Assignment,Organization Name,Organization Address).</summary>
    public static Dictionary<string, string> ParseCsv(string csv)
    {
        var table = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StringReader(csv);
        reader.ReadLine(); // cabeçalho
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var fields = SplitCsvLine(line);
            if (fields.Count < 3 || fields[1].Length != 6)
                continue;
            table[fields[1].ToUpperInvariant()] = ShortName(fields[2]);
        }
        return table;
    }

    private static List<string> SplitCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { current.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else current.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(current.ToString()); current.Clear(); }
            else current.Append(c);
        }
        fields.Add(current.ToString());
        return fields;
    }

    private static readonly (string Pattern, string Name)[] Aliases =
    [
        ("^Samsung", "Samsung"), ("Xiaomi", "Xiaomi"), ("^ASUSTek", "ASUS"), ("^Micro-Star", "MSI"),
        ("^TP-?Link", "TP-Link"), ("^Apple", "Apple"), ("^Google", "Google"), ("^Amazon", "Amazon"),
        ("^Huawei", "Huawei"), ("^Hon Hai|Foxconn", "Foxconn"), ("^Intel", "Intel"), ("^Realtek", "Realtek"),
        ("^Hewlett Packard|^HP Inc", "HP"), ("^Dell", "Dell"), ("^Lenovo", "Lenovo"), ("^LG Electronics", "LG"),
        ("^Sony", "Sony"), ("^Nintendo", "Nintendo"), ("^Microsoft", "Microsoft"), ("^Espressif", "Espressif"),
        ("^Tuya", "Tuya"), ("^GREE ELECTRIC", "Gree"), ("^Sagemcom", "Sagemcom"), ("^Raspberry Pi", "Raspberry Pi"),
        ("^Sonos", "Sonos"), ("^Philips|^Signify", "Philips"), ("^Ubiquiti", "Ubiquiti"), ("^NETGEAR", "Netgear"),
        ("^D-Link", "D-Link"), ("^AVM", "AVM (FRITZ!)"), ("^Murata", "Murata"), ("^Synology", "Synology"),
        ("^QNAP", "QNAP"), ("^Seiko Epson", "Epson"), ("^Brother", "Brother"), ("^Canon", "Canon"),
        ("^Commscope|^ARRIS", "CommScope"), ("^ZTE", "ZTE"), ("^OnePlus", "OnePlus"), ("^Motorola", "Motorola"),
        ("^Nokia", "Nokia"), ("^Ring LLC", "Ring"), ("^Roku", "Roku"), ("^Xiaomi", "Xiaomi"), ("^vivo Mobile", "vivo"),
        ("^Guangdong Oppo", "OPPO"), ("^Shenzhen Ruiming|^AltoBeam", "AltoBeam"), ("^FN-LINK", "FN-Link"),
    ];

    /// <summary>"Samsung Electronics Co.,Ltd" → "Samsung"; "Some Company Technology Co., Ltd." → "Some Company".</summary>
    public static string ShortName(string organization)
    {
        var name = organization.Trim().Trim('"');
        foreach (var (pattern, alias) in Aliases)
            if (Regex.IsMatch(name, pattern, RegexOptions.IgnoreCase))
                return alias;

        name = Regex.Replace(name,
            @"[\s,.]*(Co\.?|Company|Corp\.?|Corporation|Inc\.?|Incorporated|Ltd\.?|Limited|LLC|L\.L\.C\.|GmbH|AG|S\.?A\.?S?|SAS|S\.?p\.?A\.?|B\.?V\.?|Pty|PLC|Technologies|Technology|Tech|Electronics|Electronic|International|Intl|Holdings?|Systems|Group)\b[\s,.]*",
            " ", RegexOptions.IgnoreCase);
        name = Regex.Replace(name, @"\s{2,}", " ").Trim(' ', ',', '.', '-');
        if (name.Length == 0)
            return organization.Trim();

        // NOMES TODOS EM MAIÚSCULAS → Capitalizados (mantendo siglas curtas)
        if (name == name.ToUpperInvariant() && name.Any(char.IsLetter))
            name = string.Join(" ", name.Split(' ').Select(w => w.Length <= 3 ? w : char.ToUpperInvariant(w[0]) + w[1..].ToLowerInvariant()));
        return name;
    }

    private static Dictionary<string, string> ReadTsv(string path)
    {
        var table = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadLines(path))
        {
            var tab = line.IndexOf('\t');
            if (tab == 6)
                table[line[..6]] = line[7..];
        }
        return table;
    }

    private static void WriteTsv(string path, Dictionary<string, string> table)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllLines(temp, table.Select(kv => $"{kv.Key}\t{kv.Value}"));
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>Só para testes: substituir a tabela carregada.</summary>
    internal static void SetTableForTests(Dictionary<string, string>? table) => _table = table;
}
