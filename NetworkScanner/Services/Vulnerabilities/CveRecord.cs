namespace NetworkScanner.Services.Vulnerabilities;

/// <summary>
/// Versão compacta de um CVE da NVD: só o necessário para decidir se uma versão é afetada.
/// É o que fica guardado em cache (os JSON originais da NVD são muito maiores).
/// </summary>
public sealed class CveRecord
{
    public string Id { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime? Published { get; set; }
    public double? CvssScore { get; set; }
    public string CvssVersion { get; set; } = "";
    public string Severity { get; set; } = "Unknown";

    /// <summary>Data de inclusão no CISA KEV segundo a própria NVD (campo <c>cisaExploitAdd</c>).</summary>
    public DateTime? CisaExploitAdd { get; set; }

    /// <summary>Regras de versão aplicáveis ao produto para o qual este registo foi descarregado.</summary>
    public List<CpeMatchRule> Rules { get; set; } = [];
}

/// <summary>
/// Uma entrada <c>cpeMatch</c> da NVD com <c>vulnerable = true</c>, já filtrada para um produto.
/// </summary>
public sealed class CpeMatchRule
{
    public string Vendor { get; set; } = "";
    public string Product { get; set; } = "";

    /// <summary>Campo <c>version</c> do CPE: valor concreto, <c>*</c> (qualquer) ou <c>-</c> (não aplicável).</summary>
    public string Version { get; set; } = "*";

    /// <summary>Campo <c>update</c> do CPE (ex.: <c>p1</c> no OpenSSH).</summary>
    public string Update { get; set; } = "*";

    public string? VersionStartIncluding { get; set; }
    public string? VersionStartExcluding { get; set; }
    public string? VersionEndIncluding { get; set; }
    public string? VersionEndExcluding { get; set; }

    /// <summary>
    /// A regra vem de uma configuração AND da NVD (ex.: "OpenSSH em Red Hat Enterprise Linux 5").
    /// Como a plataforma não é conhecida, uma regra destas sem limite de versão não pode ser usada sozinha.
    /// </summary>
    public bool RequiresPlatform { get; set; }

    public bool HasRange =>
        VersionStartIncluding != null || VersionStartExcluding != null ||
        VersionEndIncluding != null || VersionEndExcluding != null;
}
