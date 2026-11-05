using System.Text.Json;

namespace NetworkScanner.Services.Vulnerabilities;

/// <summary>
/// Catálogo CISA Known Exploited Vulnerabilities (KEV): CVEs com exploração ativa confirmada.
/// https://www.cisa.gov/known-exploited-vulnerabilities-catalog
/// </summary>
public static class KevClient
{
    public const string FeedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private static readonly HttpClient Http = NvdClient.CreateHttpClient();

    public sealed class KevEntry
    {
        public DateTime? DateAdded { get; set; }
        public bool KnownRansomwareUse { get; set; }
    }

    public static async Task<Dictionary<string, KevEntry>> DownloadAsync(CancellationToken ct)
    {
        await using var stream = await Http.GetStreamAsync(FeedUrl, ct);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        return Parse(document);
    }

    public static Dictionary<string, KevEntry> Parse(JsonDocument document)
    {
        var result = new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase);
        if (!document.RootElement.TryGetProperty("vulnerabilities", out var list) || list.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Formato do catálogo KEV inesperado.");

        foreach (var item in list.EnumerateArray())
        {
            var id = item.TryGetProperty("cveID", out var idProp) ? idProp.GetString() : null;
            if (string.IsNullOrEmpty(id))
                continue;

            DateTime? added = item.TryGetProperty("dateAdded", out var dateProp) &&
                              DateTime.TryParse(dateProp.GetString(), out var date)
                ? date
                : null;

            var ransomware = item.TryGetProperty("knownRansomwareCampaignUse", out var r) &&
                             string.Equals(r.GetString(), "Known", StringComparison.OrdinalIgnoreCase);

            result[id] = new KevEntry { DateAdded = added, KnownRansomwareUse = ransomware };
        }

        return result;
    }
}
