using System.Globalization;
using System.Text.Json;

namespace Nodar.Core.Services.Vulnerabilities;

/// <summary>
/// Converte respostas da NVD CVE API 2.0 em <see cref="CveRecord"/> compactos.
/// </summary>
public static class NvdParser
{
    public sealed record Page(List<CveRecord> Records, int TotalResults, int ResultsPerPage, int StartIndex);

    /// <summary>
    /// Lê uma página de resultados e guarda apenas as regras <c>cpeMatch</c> vulneráveis
    /// do par <paramref name="vendor"/>:<paramref name="product"/> (parte "a", aplicação).
    /// </summary>
    public static Page ParsePage(JsonDocument document, string vendor, string product)
    {
        var root = document.RootElement;
        var records = new List<CveRecord>();

        if (root.TryGetProperty("vulnerabilities", out var vulnerabilities) &&
            vulnerabilities.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in vulnerabilities.EnumerateArray())
            {
                if (!item.TryGetProperty("cve", out var cve))
                    continue;

                var record = ParseCve(cve, vendor, product);
                if (record != null)
                    records.Add(record);
            }
        }

        return new Page(
            records,
            GetInt(root, "totalResults"),
            GetInt(root, "resultsPerPage"),
            GetInt(root, "startIndex"));
    }

    public static CveRecord? ParseCve(JsonElement cve, string vendor, string product)
    {
        var id = GetString(cve, "id");
        if (string.IsNullOrEmpty(id))
            return null;

        if (string.Equals(GetString(cve, "vulnStatus"), "Rejected", StringComparison.OrdinalIgnoreCase))
            return null;

        var rules = ExtractRules(cve, vendor, product);
        if (rules.Count == 0)
            return null; // sem regras de versão para este produto: não é possível decidir nada

        var (score, cvssVersion, severity) = ExtractCvss(cve);

        return new CveRecord
        {
            Id = id,
            Description = ExtractDescription(cve),
            Published = ParseDate(GetString(cve, "published")),
            CvssScore = score,
            CvssVersion = cvssVersion,
            Severity = severity,
            CisaExploitAdd = ParseDate(GetString(cve, "cisaExploitAdd")),
            Rules = rules
        };
    }

    private static List<CpeMatchRule> ExtractRules(JsonElement cve, string vendor, string product)
    {
        var rules = new List<CpeMatchRule>();
        if (!cve.TryGetProperty("configurations", out var configurations) ||
            configurations.ValueKind != JsonValueKind.Array)
            return rules;

        foreach (var configuration in configurations.EnumerateArray())
        {
            if (!configuration.TryGetProperty("nodes", out var nodes) || nodes.ValueKind != JsonValueKind.Array)
                continue;

            // AND entre nós (produto + plataforma). Também conta como dependente da plataforma um único nó
            // AND que misture CPEs vulneráveis e não vulneráveis.
            var requiresPlatform =
                string.Equals(GetString(configuration, "operator"), "AND", StringComparison.OrdinalIgnoreCase) &&
                nodes.GetArrayLength() > 1 ||
                nodes.EnumerateArray().Any(n =>
                    string.Equals(GetString(n, "operator"), "AND", StringComparison.OrdinalIgnoreCase) &&
                    n.TryGetProperty("cpeMatch", out var m) && m.ValueKind == JsonValueKind.Array &&
                    m.EnumerateArray().Any(x => x.TryGetProperty("vulnerable", out var v) && v.ValueKind == JsonValueKind.False));

            foreach (var node in nodes.EnumerateArray())
            {
                // Nós negados ("NOT ...") excluem em vez de incluir: ignorados.
                if (node.TryGetProperty("negate", out var negate) && negate.ValueKind == JsonValueKind.True)
                    continue;
                if (!node.TryGetProperty("cpeMatch", out var matches) || matches.ValueKind != JsonValueKind.Array)
                    continue;

                foreach (var match in matches.EnumerateArray())
                {
                    if (!match.TryGetProperty("vulnerable", out var vulnerable) || vulnerable.ValueKind != JsonValueKind.True)
                        continue;

                    var parts = CpeMatcher.SplitCpe(GetString(match, "criteria"));
                    if (parts == null || parts[2] != "a")
                        continue;
                    if (!string.Equals(parts[3], vendor, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(parts[4], product, StringComparison.OrdinalIgnoreCase))
                        continue;

                    rules.Add(new CpeMatchRule
                    {
                        Vendor = parts[3],
                        Product = parts[4],
                        Version = parts[5],
                        Update = parts[6],
                        VersionStartIncluding = GetOptionalString(match, "versionStartIncluding"),
                        VersionStartExcluding = GetOptionalString(match, "versionStartExcluding"),
                        VersionEndIncluding = GetOptionalString(match, "versionEndIncluding"),
                        VersionEndExcluding = GetOptionalString(match, "versionEndExcluding"),
                        RequiresPlatform = requiresPlatform,
                    });
                }
            }
        }

        return rules;
    }

    /// <summary>
    /// Escolhe a métrica CVSS mais recente disponível (v4.0 → v3.1 → v3.0 → v2), preferindo a fonte "Primary" (NVD).
    /// </summary>
    private static (double? Score, string Version, string Severity) ExtractCvss(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics))
            return (null, "", "Unknown");

        foreach (var key in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
        {
            if (!metrics.TryGetProperty(key, out var list) || list.ValueKind != JsonValueKind.Array || list.GetArrayLength() == 0)
                continue;

            var chosen = list.EnumerateArray()
                .OrderBy(m => GetString(m, "type") == "Primary" ? 0 : 1)
                .First();

            if (!chosen.TryGetProperty("cvssData", out var data))
                continue;

            double? score = data.TryGetProperty("baseScore", out var s) && s.ValueKind == JsonValueKind.Number
                ? s.GetDouble()
                : null;

            // Em v3/v4 a severidade está em cvssData; em v2 está no nível da métrica.
            var severity = GetString(data, "baseSeverity");
            if (string.IsNullOrEmpty(severity))
                severity = GetString(chosen, "baseSeverity");

            return (score, GetString(data, "version"), NormalizeSeverity(severity, score));
        }

        return (null, "", "Unknown");
    }

    public static string NormalizeSeverity(string? severity, double? score)
    {
        switch (severity?.ToUpperInvariant())
        {
            case "CRITICAL": return "Critical";
            case "HIGH": return "High";
            case "MEDIUM": return "Medium";
            case "LOW": return "Low";
            case "NONE": return "None";
        }

        // Escala CVSS v3 como último recurso.
        return score switch
        {
            null => "Unknown",
            >= 9.0 => "Critical",
            >= 7.0 => "High",
            >= 4.0 => "Medium",
            > 0 => "Low",
            _ => "None"
        };
    }

    private static string ExtractDescription(JsonElement cve)
    {
        if (!cve.TryGetProperty("descriptions", out var descriptions) || descriptions.ValueKind != JsonValueKind.Array)
            return "";

        string? fallback = null;
        foreach (var description in descriptions.EnumerateArray())
        {
            var value = GetString(description, "value");
            if (GetString(description, "lang") == "en")
                return value;
            fallback ??= value;
        }
        return fallback ?? "";
    }

    private static DateTime? ParseDate(string? value) =>
        DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var date)
            ? date
            : null;

    private static string GetString(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? ""
            : "";

    private static string? GetOptionalString(JsonElement element, string name)
    {
        var value = GetString(element, name);
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static int GetInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetInt32() : 0;
}
