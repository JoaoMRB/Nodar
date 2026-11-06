using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nodar.Core.Models;

namespace Nodar.Core.Services;

/// <summary>
/// Olha para o TLS dos serviços: o certificado (validade, chave, assinatura), o protocolo negociado e se o servidor
/// ainda aceita protocolos obsoletos (SSL 3.0, TLS 1.0 e 1.1).
/// </summary>
/// <remarks>
/// <para>O certificado e o protocolo vêm de um handshake normal, sem validar a cadeia (routers e IoT usam
/// certificados autoassinados) e sem enviar dados nenhuns depois dele.</para>
/// <para>Os protocolos antigos não se testam com o <c>SslStream</c>: o Windows recente já os recusa no cliente, e
/// o teste diria "recusado" por culpa nossa. Em vez disso envia-se só um <c>ClientHello</c> que oferece essa versão
/// e olha-se para a resposta (um <c>ServerHello</c> com a mesma versão = aceita; um alerta = recusa). A ligação
/// fecha logo a seguir: não há troca de chaves nem dados.</para>
/// </remarks>
public static class TlsInspector
{
    /// <summary>Portas em que o serviço fala TLS logo à cabeça (HTTPS, HTTPS alternativo, IMAPS, POP3S).</summary>
    public static readonly IReadOnlySet<int> TlsPorts = new HashSet<int> { 443, 8443, 993, 995 };

    public sealed record InspectOptions
    {
        public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(2);
        public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(3);
        public TimeSpan ProbeTimeout { get; init; } = TimeSpan.FromSeconds(1.5);

        /// <summary>Testar também os protocolos obsoletos (três ligações extra por porta).</summary>
        public bool CheckLegacy { get; init; } = true;

        public static InspectOptions Default { get; } = new();
    }

    private static readonly (string Name, ushort Version)[] LegacyVersions =
        [("SSL 3.0", 0x0300), ("TLS 1.0", 0x0301), ("TLS 1.1", 0x0302)];

    /// <summary>Inspeciona os serviços que falam TLS e guarda o resultado em <see cref="ServiceInfo.Tls"/>.</summary>
    public static async Task AttachAsync(string ip, IEnumerable<ServiceInfo> services, CancellationToken ct)
    {
        foreach (var service in services.Where(s => TlsPorts.Contains(s.Port)))
            service.Tls = await InspectAsync(ip, service.Port, ct);
    }

    /// <returns>O que o serviço mostrou, ou <c>null</c> se não fala TLS (ou não respondeu a tempo).</returns>
    public static async Task<TlsInfo?> InspectAsync(string ip, int port, CancellationToken ct, InspectOptions? options = null)
    {
        options ??= InspectOptions.Default;
        var info = await HandshakeAsync(ip, port, options, ct);
        if (info != null && options.CheckLegacy)
            info.LegacyProtocols.AddRange(await LegacyProtocolsAsync(ip, port, ct, options));
        return info;
    }

    /// <summary>Os protocolos obsoletos (SSL 3.0, TLS 1.0, TLS 1.1) que o servidor aceita.</summary>
    public static async Task<List<string>> LegacyProtocolsAsync(string ip, int port, CancellationToken ct, InspectOptions? options = null)
    {
        options ??= InspectOptions.Default;
        var accepted = new List<string>();
        foreach (var (name, version) in LegacyVersions)
            if (await AcceptsAsync(ip, port, version, options, ct))
                accepted.Add(name);
        return accepted;
    }

    // ---------------------------------------------------------------- Certificado e protocolo negociado

    private static async Task<TlsInfo?> HandshakeAsync(string ip, int port, InspectOptions options, CancellationToken ct)
    {
        using var client = new TcpClient();
        try
        {
            using (var connect = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connect.CancelAfter(options.ConnectTimeout);
                await client.ConnectAsync(IPAddress.Parse(ip), port, connect.Token);
            }

            await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            TlsInfo? info = null;
            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct);
            handshake.CancelAfter(options.HandshakeTimeout);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = ip,
                // A cadeia não se valida de propósito: o que interessa é o que o certificado diz, e routers e
                // dispositivos IoT usam quase sempre certificados autoassinados. Depois do handshake não se envia nada.
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    if (certificate != null)
                    {
                        using var copy = new X509Certificate2(certificate);
                        info = Describe(copy);
                    }
                    return true;
                },
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, handshake.Token);

            if (info != null)
                info.Protocol = ProtocolName(ssl.SslProtocol);
            return info;
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, $"TLS da porta {port}", ct))
        {
            return null; // não fala TLS, recusou ou não respondeu a tempo
        }
    }

    internal static TlsInfo Describe(X509Certificate2 certificate)
    {
        string name(bool issuer) => certificate.GetNameInfo(X509NameType.SimpleName, issuer);

        var size = 0;
        using (var rsa = certificate.GetRSAPublicKey())
            size = rsa?.KeySize ?? 0;
        if (size == 0)
            using (var ecdsa = certificate.GetECDsaPublicKey())
                size = ecdsa?.KeySize ?? 0;

        return new TlsInfo
        {
            Subject = name(false),
            Issuer = name(true),
            NotBefore = certificate.NotBefore,
            NotAfter = certificate.NotAfter,
            Fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData)),
            SelfSigned = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData),
            KeyAlgorithm = certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "",
            KeySize = size,
            SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? ""
        };
    }

    private static string ProtocolName(System.Security.Authentication.SslProtocols protocol) => protocol switch
    {
        System.Security.Authentication.SslProtocols.Tls13 => "TLS 1.3",
        System.Security.Authentication.SslProtocols.Tls12 => "TLS 1.2",
#pragma warning disable SYSLIB0039 // TLS 1.0 e 1.1 estão obsoletos: aqui só se lhes dá o nome
        System.Security.Authentication.SslProtocols.Tls11 => "TLS 1.1",
        System.Security.Authentication.SslProtocols.Tls => "TLS 1.0",
#pragma warning restore SYSLIB0039
        _ => protocol.ToString()
    };

    // ---------------------------------------------------------------- Protocolos obsoletos

    private static async Task<bool> AcceptsAsync(string ip, int port, ushort version, InspectOptions options, CancellationToken ct)
    {
        using var client = new TcpClient();
        try
        {
            using (var connect = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connect.CancelAfter(options.ConnectTimeout);
                await client.ConnectAsync(IPAddress.Parse(ip), port, connect.Token);
            }

            var stream = client.GetStream();
            await stream.WriteAsync(BuildClientHello(version), ct);

            // Cabeçalho do registo (5) + tipo e tamanho do handshake (4) + versão do servidor (2).
            using var read = CancellationTokenSource.CreateLinkedTokenSource(ct);
            read.CancelAfter(options.ProbeTimeout);
            var head = new byte[11];
            var got = 0;
            while (got < head.Length)
            {
                var n = await stream.ReadAsync(head.AsMemory(got), read.Token);
                if (n == 0)
                    break;
                got += n;
            }
            return got == head.Length && IsServerHello(head, version);
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, $"Sonda de protocolo TLS da porta {port}", ct))
        {
            return false; // sem resposta a tempo, ligação fechada ou recusada
        }
    }

    /// <summary>Handshake (0x16) cujo primeiro registo é um ServerHello (0x02) exatamente na versão oferecida.</summary>
    public static bool IsServerHello(ReadOnlySpan<byte> head, ushort offered) =>
        head.Length >= 11 && head[0] == 0x16 && head[5] == 0x02 && ((head[9] << 8) | head[10]) == offered;

    /// <summary>
    /// Um <c>ClientHello</c> mínimo que oferece só <paramref name="version"/> e suítes de cifra da época
    /// (RSA e ECDHE com AES e 3DES). Não há dados de cliente: o servidor responde e fecha-se a ligação.
    /// </summary>
    public static byte[] BuildClientHello(ushort version)
    {
        ushort[] suites = [0xC014, 0xC013, 0xC00A, 0xC009, 0x0035, 0x002F, 0x0039, 0x0033, 0x000A];

        var body = new List<byte> { (byte)(version >> 8), (byte)version };
        body.AddRange(RandomNumberGenerator.GetBytes(32));
        body.Add(0);                                           // sem sessão anterior
        body.Add((byte)(suites.Length * 2 >> 8));
        body.Add((byte)(suites.Length * 2));
        foreach (var suite in suites)
        {
            body.Add((byte)(suite >> 8));
            body.Add((byte)suite);
        }
        body.AddRange([1, 0]);                                 // compressão: nenhuma

        if (version >= 0x0301)                                 // o SSL 3.0 não tem extensões
        {
            byte[] extensions =
            [
                0x00, 0x0A, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, // grupos: secp256r1, secp384r1
                0x00, 0x0B, 0x00, 0x02, 0x01, 0x00                          // formatos de ponto: não comprimido
            ];
            body.Add((byte)(extensions.Length >> 8));
            body.Add((byte)extensions.Length);
            body.AddRange(extensions);
        }

        var handshake = new List<byte> { 0x01, (byte)(body.Count >> 16), (byte)(body.Count >> 8), (byte)body.Count };
        handshake.AddRange(body);

        var recordVersion = version == 0x0300 ? (ushort)0x0300 : (ushort)0x0301;
        var record = new List<byte> { 0x16, (byte)(recordVersion >> 8), (byte)recordVersion, (byte)(handshake.Count >> 8), (byte)handshake.Count };
        record.AddRange(handshake);
        return [.. record];
    }
}
