using System.Text.Json;
using NetworkScanner.Services.Vulnerabilities;

namespace Nodar.Tests;

public class CpeMatcherTests
{
    private static CveRecord LoadRegreSSHion()
    {
        // Resposta real da NVD para CVE-2024-6387 ("regreSSHion").
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "nvd_CVE-2024-6387.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var page = NvdParser.ParsePage(doc, "openbsd", "openssh");
        return Assert.Single(page.Records);
    }

    // Segundo o aviso da Qualys: afetadas 8.5p1 até antes de 9.8p1; 4.4p1 até antes de 8.5p1 não afetadas;
    // anteriores a 4.4p1 afetadas (se sem patch para CVE-2006-5051).
    [Theory]
    [InlineData("8.5p1", true)]
    [InlineData("8.9p1", true)]
    [InlineData("9.3p2", true)]
    [InlineData("9.7p1", true)]
    [InlineData("9.8p1", false)]  // versão que corrigiu a falha
    [InlineData("9.9p1", false)]
    [InlineData("8.2p1", false)]
    [InlineData("7.4p1", false)]
    [InlineData("4.4p1", false)]
    [InlineData("4.3p2", true)]
    [InlineData("3.9p1", true)]
    public void RegreSSHion_matches_only_affected_versions(string version, bool expected)
    {
        var cve = LoadRegreSSHion();
        Assert.Equal(expected, CpeMatcher.IsAffected(cve, version));
    }

    [Theory]
    [InlineData("4.3p2")]
    [InlineData("8.9p1")]
    [InlineData("9.9p1")]
    public void Platform_only_cve_does_not_match_every_version(string version)
    {
        // CVE-2008-3844: "OpenSSH (todas as versões) AND Red Hat Enterprise Linux 4/5" (pacotes adulterados).
        // Sem conhecer a plataforma, não pode ser atribuída a qualquer OpenSSH.
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "nvd_CVE-2008-3844.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var cve = Assert.Single(NvdParser.ParsePage(doc, "openbsd", "openssh").Records);
        Assert.All(cve.Rules, r => Assert.True(r.RequiresPlatform));
        Assert.False(CpeMatcher.IsAffected(cve, version));
    }

    [Fact]
    public void Platform_bound_rule_with_version_range_still_matches()
    {
        var rule = new CpeMatchRule { Version = "*", VersionEndExcluding = "2.0", RequiresPlatform = true };
        Assert.True(CpeMatcher.Matches(rule, "1.5"));
        Assert.False(CpeMatcher.Matches(rule, "2.0"));
    }

    [Fact]
    public void Empty_version_never_matches()
    {
        var rule = new CpeMatchRule { Version = "*" };
        Assert.False(CpeMatcher.Matches(rule, ""));
    }

    [Fact]
    public void Wildcard_without_range_matches_all_versions()
    {
        var rule = new CpeMatchRule { Version = "*" };
        Assert.True(CpeMatcher.Matches(rule, "1.2.3"));
    }

    [Fact]
    public void Not_applicable_version_without_range_is_ignored()
    {
        var rule = new CpeMatchRule { Version = "-" };
        Assert.False(CpeMatcher.Matches(rule, "1.2.3"));
    }

    [Theory]
    [InlineData("2.4.49", true)]
    [InlineData("2.4.50", false)]   // endExcluding
    [InlineData("2.4.30", false)]   // antes de startIncluding
    [InlineData("2.4.31", true)]
    public void Range_bounds_are_respected(string version, bool expected)
    {
        var rule = new CpeMatchRule
        {
            Version = "*",
            VersionStartIncluding = "2.4.31",
            VersionEndExcluding = "2.4.50"
        };
        Assert.Equal(expected, CpeMatcher.Matches(rule, version));
    }

    [Theory]
    [InlineData("1.3.5", "*", "1.3.5e", true)]   // update=* aceita qualquer sufixo
    [InlineData("1.3.5", "-", "1.3.5e", false)]  // update=- exige exatamente a versão
    [InlineData("1.3.5", "-", "1.3.5", true)]
    [InlineData("8.5", "p1", "8.5p1", true)]
    [InlineData("8.5", "p1", "8.5p2", false)]
    public void Exact_version_and_update_semantics(string ruleVersion, string ruleUpdate, string detected, bool expected)
    {
        var rule = new CpeMatchRule { Version = ruleVersion, Update = ruleUpdate };
        Assert.Equal(expected, CpeMatcher.Matches(rule, detected));
    }

    [Fact]
    public void SplitCpe_handles_escaped_colons()
    {
        var parts = CpeMatcher.SplitCpe(@"cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*");
        Assert.NotNull(parts);
        Assert.Equal("prod:uct", parts![4]);
        Assert.Equal("1.0", parts[5]);
    }

    [Fact]
    public void SplitCpe_rejects_non_cpe()
    {
        Assert.Null(CpeMatcher.SplitCpe("not-a-cpe"));
    }
}
