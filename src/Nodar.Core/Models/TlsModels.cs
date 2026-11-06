namespace Nodar.Core.Models;

/// <summary>O que um serviço TLS mostrou: o certificado, o protocolo negociado e os protocolos antigos que ainda aceita.</summary>
public sealed class TlsInfo
{
    /// <summary>Protocolo negociado num handshake normal (ex.: "TLS 1.3").</summary>
    public string Protocol { get; set; } = "";

    /// <summary>Nome do titular (o CN, ou o nome completo se não houver).</summary>
    public string Subject { get; init; } = "";
    public string Issuer { get; init; } = "";
    public DateTime NotBefore { get; init; }
    public DateTime NotAfter { get; init; }

    /// <summary>Impressão digital SHA-256 do certificado, em hexadecimal.</summary>
    public string Fingerprint { get; init; } = "";

    /// <summary>Titular e emissor iguais (comum em routers e IoT; sozinho não é um problema).</summary>
    public bool SelfSigned { get; init; }

    /// <summary>"RSA", "ECC"…</summary>
    public string KeyAlgorithm { get; init; } = "";
    public int KeySize { get; init; }

    /// <summary>Ex.: "sha256RSA".</summary>
    public string SignatureAlgorithm { get; init; } = "";

    /// <summary>Protocolos obsoletos que o servidor aceita ("SSL 3.0", "TLS 1.0", "TLS 1.1").</summary>
    public List<string> LegacyProtocols { get; } = [];

    /// <summary>Outros dispositivos da rede com este mesmo certificado autoassinado (preenchido depois do scan).</summary>
    public List<string> SharedWith { get; set; } = [];
}

public enum TlsFindingKind
{
    Expired,
    NotYetValid,
    ExpiresSoon,
    LegacyProtocol,
    WeakKey,
    WeakSignature,
    SharedCertificate
}

/// <summary>Um problema num serviço TLS. O texto para o utilizador é feito pela interface (idioma).</summary>
/// <param name="Severity">Critical, High, Medium ou Low (como nas vulnerabilidades).</param>
/// <param name="Arg">Dado de apoio: protocolos aceites, algoritmo, dispositivos com o mesmo certificado.</param>
/// <param name="When">Data relevante (expiração ou início de validade).</param>
/// <param name="Number">Número de apoio (tamanho da chave).</param>
public sealed record TlsFinding(TlsFindingKind Kind, string Severity, int Port, string Arg = "", DateTime? When = null, int Number = 0);
