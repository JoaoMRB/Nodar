using System.Text;

namespace NetworkScanner.Services.Vulnerabilities;

/// <summary>
/// Decide se uma versão detetada é afetada pelas regras <c>cpeMatch</c> da NVD.
/// </summary>
/// <remarks>
/// Semântica seguida (CPE 2.3 / NVD API 2.0):
/// <list type="bullet">
/// <item>Regra com intervalo (<c>versionStart*/versionEnd*</c>): a versão completa detetada (incluindo sufixos
/// como <c>p1</c>) tem de estar dentro dos limites. Ex.: com <c>versionEndIncluding = 9.8</c>, <c>9.7p1</c> é
/// afetada e <c>9.8p1</c> não (9.8p1 &gt; 9.8).</item>
/// <item>Regra com versão concreta: a versão detetada tem de ser igual a <c>version</c>+<c>update</c>.
/// Se <c>update = *</c> (qualquer), basta a parte numérica coincidir. Se <c>update = -</c> (não aplicável),
/// a versão tem de coincidir exatamente.</item>
/// <item>Regra com <c>version = *</c> e sem limites: todas as versões são afetadas.</item>
/// <item>Regra com <c>version = -</c> e sem limites: não é possível decidir por versão, por isso é ignorada.</item>
/// </list>
/// Configurações AND da NVD (ex.: "produto X a correr no sistema Y"): a plataforma não é conhecida, por isso
/// basta a regra do produto coincidir, exceto quando essa regra abrange todas as versões sem limite,
/// caso em que é a plataforma que decide e a regra é ignorada (<see cref="CpeMatchRule.RequiresPlatform"/>).
/// Os resultados são apresentados como <em>potenciais</em>.
/// </remarks>
public static class CpeMatcher
{
    public static bool IsAffected(CveRecord cve, string detectedVersion) =>
        cve.Rules.Any(rule => Matches(rule, detectedVersion));

    public static bool Matches(CpeMatchRule rule, string detectedVersion)
    {
        if (string.IsNullOrWhiteSpace(detectedVersion))
            return false;

        if (rule.HasRange)
            return InRange(rule, detectedVersion);

        if (rule.Version == "*")
        {
            // "Todas as versões" condicionadas a uma plataforma (AND) dependem da plataforma, não da versão.
            // Ex.: CVE-2008-3844 (pacotes OpenSSH adulterados só no RHEL 4/5).
            return !rule.RequiresPlatform;
        }

        if (rule.Version == "-" || string.IsNullOrEmpty(rule.Version))
            return false;

        return MatchesExact(rule, detectedVersion);
    }

    private static bool InRange(CpeMatchRule rule, string version)
    {
        // Se a regra com intervalo tiver também uma versão concreta (raro), ela tem de coincidir.
        if (rule.Version is not ("*" or "-" or "") && !MatchesExact(rule, version))
            return false;

        if (rule.VersionStartIncluding != null && VersionComparer.Compare(version, rule.VersionStartIncluding) < 0)
            return false;
        if (rule.VersionStartExcluding != null && VersionComparer.Compare(version, rule.VersionStartExcluding) <= 0)
            return false;
        if (rule.VersionEndIncluding != null && VersionComparer.Compare(version, rule.VersionEndIncluding) > 0)
            return false;
        if (rule.VersionEndExcluding != null && VersionComparer.Compare(version, rule.VersionEndExcluding) >= 0)
            return false;

        return true;
    }

    private static bool MatchesExact(CpeMatchRule rule, string version)
    {
        var update = rule.Update ?? "*";

        if (update == "*")
        {
            // Qualquer update: comparar a versão completa ou, se a regra não tiver sufixo, só a parte numérica.
            if (VersionComparer.AreEqual(version, rule.Version))
                return true;
            var ruleBase = VersionComparer.GetNumericBase(rule.Version);
            return ruleBase == rule.Version && VersionComparer.AreEqual(VersionComparer.GetNumericBase(version), ruleBase);
        }

        if (update is "-" or "")
            return VersionComparer.AreEqual(version, rule.Version);

        return VersionComparer.AreEqual(version, rule.Version + update);
    }

    /// <summary>
    /// Divide um CPE 2.3 formatado (<c>cpe:2.3:part:vendor:product:version:update:...</c>) respeitando
    /// os caracteres escapados com <c>\</c>. Devolve <c>null</c> se não for um CPE 2.3 válido.
    /// </summary>
    public static string[]? SplitCpe(string cpe)
    {
        if (string.IsNullOrEmpty(cpe) || !cpe.StartsWith("cpe:2.3:", StringComparison.OrdinalIgnoreCase))
            return null;

        var parts = new List<string>(13);
        var current = new StringBuilder();
        for (var i = 0; i < cpe.Length; i++)
        {
            var c = cpe[i];
            if (c == '\\' && i + 1 < cpe.Length)
            {
                current.Append(cpe[++i]);
                continue;
            }
            if (c == ':')
            {
                parts.Add(current.ToString());
                current.Clear();
                continue;
            }
            current.Append(c);
        }
        parts.Add(current.ToString());

        return parts.Count >= 7 ? parts.ToArray() : null;
    }
}
