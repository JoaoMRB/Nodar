using Nodar.Core.Models;

namespace Nodar.Core.Services;

/// <summary>Transforma o que o <see cref="TlsInspector"/> viu em problemas concretos.</summary>
/// <remarks>
/// Não se assinala um certificado só por ser autoassinado: quase todos os routers, câmaras e NAS o são, e a
/// lista ficaria cheia de ruído. Também só se assinala "certificado partilhado" quando é autoassinado: um
/// certificado de uma autoridade (por exemplo um wildcard) em vários servidores do mesmo dono é normal.
/// </remarks>
public static class TlsAnalyzer
{
    public const int ExpiresSoonDays = 30;

    private const int MinRsaBits = 2048;
    private const int MinEccBits = 224;

    public static List<TlsFinding> Analyze(TlsInfo tls, int port, DateTime now)
    {
        var findings = new List<TlsFinding>();

        if (tls.NotAfter < now)
            findings.Add(new(TlsFindingKind.Expired, "Medium", port, When: tls.NotAfter));
        else if (tls.NotBefore > now)
            findings.Add(new(TlsFindingKind.NotYetValid, "Low", port, When: tls.NotBefore)); // costuma ser o relógio do dispositivo
        else if (tls.NotAfter - now <= TimeSpan.FromDays(ExpiresSoonDays))
            findings.Add(new(TlsFindingKind.ExpiresSoon, "Low", port, When: tls.NotAfter));

        if (tls.LegacyProtocols.Count > 0)
            findings.Add(new(TlsFindingKind.LegacyProtocol,
                tls.LegacyProtocols.Contains("SSL 3.0") ? "High" : "Medium", port, string.Join(", ", tls.LegacyProtocols)));

        var weakKey = tls.KeySize > 0 && tls.KeyAlgorithm switch
        {
            "RSA" => tls.KeySize < MinRsaBits,
            "ECC" => tls.KeySize < MinEccBits,
            _ => false
        };
        if (weakKey)
            findings.Add(new(TlsFindingKind.WeakKey, "High", port, tls.KeyAlgorithm, Number: tls.KeySize));

        if (IsWeakSignature(tls.SignatureAlgorithm))
            findings.Add(new(TlsFindingKind.WeakSignature, "Medium", port, tls.SignatureAlgorithm));

        if (tls.SelfSigned && tls.SharedWith.Count > 0)
            findings.Add(new(TlsFindingKind.SharedCertificate, "High", port, string.Join(", ", tls.SharedWith)));

        return findings;
    }

    private static bool IsWeakSignature(string algorithm) =>
        algorithm.Contains("md5", StringComparison.OrdinalIgnoreCase)
        || algorithm.Contains("md2", StringComparison.OrdinalIgnoreCase)
        || algorithm.Contains("sha1", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Marca os certificados autoassinados que aparecem em mais do que um dispositivo. É o rasto de um certificado
    /// (e da chave privada) de fábrica, igual em todos os aparelhos do modelo: quem a extrair do firmware pode
    /// fazer-se passar por qualquer um deles.
    /// </summary>
    public static void MarkShared(IEnumerable<DeviceInfo> devices)
    {
        var withTls = devices
            .SelectMany(d => d.Services.Where(s => s.Tls is { SelfSigned: true }).Select(s => (d.IpAddress, Tls: s.Tls!)))
            .ToList();

        foreach (var group in withTls.GroupBy(x => x.Tls.Fingerprint, StringComparer.Ordinal))
        {
            var ips = group.Select(x => x.IpAddress).Distinct(StringComparer.Ordinal).ToList();
            if (ips.Count < 2)
                continue; // o mesmo certificado em duas portas do mesmo dispositivo não conta
            foreach (var (ip, tls) in group)
                tls.SharedWith = ips.Where(other => other != ip).ToList();
        }
    }
}
