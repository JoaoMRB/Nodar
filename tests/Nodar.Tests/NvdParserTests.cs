using System.Text.Json;
using Nodar.Core.Services.Vulnerabilities;

namespace Nodar.Tests;

public class NvdParserTests
{
    private static JsonDocument Fixture() => JsonDocument.Parse(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "nvd_CVE-2024-6387.json")));

    [Fact]
    public void Parses_real_nvd_record()
    {
        using var doc = Fixture();
        var page = NvdParser.ParsePage(doc, "openbsd", "openssh");

        Assert.Equal(1, page.TotalResults);
        var cve = Assert.Single(page.Records);
        Assert.Equal("CVE-2024-6387", cve.Id);
        Assert.Equal(8.1, cve.CvssScore);
        Assert.Equal("3.1", cve.CvssVersion);
        Assert.Equal("High", cve.Severity);
        Assert.False(string.IsNullOrWhiteSpace(cve.Description));
        Assert.NotNull(cve.Published);

        // Só as regras do OpenSSH, não as de outros produtos (SonicWall, NetApp…) no mesmo CVE.
        Assert.All(cve.Rules, r => Assert.Equal("openssh", r.Product));
        Assert.Equal(5, cve.Rules.Count);
    }

    [Fact]
    public void Other_products_in_same_cve_are_filtered_out()
    {
        using var doc = Fixture();
        var page = NvdParser.ParsePage(doc, "apache", "http_server");
        Assert.Empty(page.Records);
    }

    [Fact]
    public void Rejected_and_rule_less_cves_are_skipped()
    {
        const string json = """
        {
          "resultsPerPage": 2, "startIndex": 0, "totalResults": 2,
          "vulnerabilities": [
            { "cve": { "id": "CVE-0000-0001", "vulnStatus": "Rejected",
                       "configurations": [ { "nodes": [ { "cpeMatch": [
                         { "vulnerable": true, "criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*" } ] } ] } ] } },
            { "cve": { "id": "CVE-0000-0002", "vulnStatus": "Awaiting Analysis" } }
          ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        Assert.Empty(NvdParser.ParsePage(doc, "x", "y").Records);
    }

    [Fact]
    public void Non_vulnerable_and_negated_matches_are_ignored()
    {
        const string json = """
        {
          "totalResults": 1, "resultsPerPage": 1, "startIndex": 0,
          "vulnerabilities": [ { "cve": {
            "id": "CVE-0000-0003", "vulnStatus": "Analyzed",
            "configurations": [ { "operator": "AND", "nodes": [
              { "negate": true,  "cpeMatch": [ { "vulnerable": true,  "criteria": "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*" } ] },
              { "negate": false, "cpeMatch": [ { "vulnerable": false, "criteria": "cpe:2.3:a:x:y:2.0:*:*:*:*:*:*:*" } ] },
              { "negate": false, "cpeMatch": [ { "vulnerable": true,  "criteria": "cpe:2.3:a:x:y:3.0:*:*:*:*:*:*:*" } ] }
            ] } ]
          } } ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var rule = Assert.Single(Assert.Single(NvdParser.ParsePage(doc, "x", "y").Records).Rules);
        Assert.Equal("3.0", rule.Version);
    }

    [Fact]
    public void Prefers_newest_cvss_and_reads_v2_severity_from_metric_level()
    {
        const string json = """
        {
          "totalResults": 1, "resultsPerPage": 1, "startIndex": 0,
          "vulnerabilities": [ { "cve": {
            "id": "CVE-2010-0001", "vulnStatus": "Analyzed",
            "metrics": { "cvssMetricV2": [ { "source": "nvd@nist.gov", "type": "Primary",
                          "cvssData": { "version": "2.0", "baseScore": 7.5 }, "baseSeverity": "HIGH" } ] },
            "configurations": [ { "nodes": [ { "cpeMatch": [
              { "vulnerable": true, "criteria": "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*" } ] } ] } ]
          } } ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var cve = Assert.Single(NvdParser.ParsePage(doc, "x", "y").Records);
        Assert.Equal(7.5, cve.CvssScore);
        Assert.Equal("2.0", cve.CvssVersion);
        Assert.Equal("High", cve.Severity);
    }

    [Theory]
    [InlineData("CRITICAL", null, "Critical")]
    [InlineData("medium", null, "Medium")]
    [InlineData(null, 9.8, "Critical")]
    [InlineData(null, 5.0, "Medium")]
    [InlineData(null, null, "Unknown")]
    public void NormalizeSeverity(string? severity, double? score, string expected) =>
        Assert.Equal(expected, NvdParser.NormalizeSeverity(severity, score));
}
