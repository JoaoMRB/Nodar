using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Nodar.Core.Models;

namespace Nodar.Core.Services;

/// <summary>
/// O que a internet vê do teu endereço público, segundo o Shodan InternetDB (gratuito, sem conta nem chave).
/// </summary>
/// <remarks>
/// <para><b>Privacidade:</b> é a única função do Nodar que envia algo para fora do computador sobre a tua rede:
/// o endereço público. Por isso nunca corre sozinha: só quando o utilizador a pede.</para>
/// <para>O endereço vem, de preferência, do próprio router (UPnP), sem perguntar a ninguém. Só se o router não o
/// disser é que se pergunta a um serviço de "qual é o meu IP". Se o endereço do router não for público (CGNAT ou
/// duplo NAT) não se consulta nada: o que o Shodan visse seria de outros clientes do operador.</para>
/// <para>Os dados do Shodan são da última vez que ele passou por esse endereço: podem ter dias.</para>
/// </remarks>
public static partial class InternetExposureService
{
    public static readonly Uri LookupBase = new("https://internetdb.shodan.io/");
    public static readonly Uri PublicIpEndpoint = new("https://api.ipify.org/");

    private const int MaxItems = 200;

    /// <param name="knownPublicIp">Endereço externo dito pelo router (<c>null</c> se não se sabe).</param>
    /// <param name="handler">Só para testes.</param>
    public static async Task<InternetExposure> CheckAsync(string? knownPublicIp, CancellationToken ct,
        HttpMessageHandler? handler = null, Func<DateTime>? clock = null)
    {
        var now = (clock ?? (() => DateTime.Now))();
        InternetExposure Result(InternetCheckStatus status, string ip = "") =>
            new() { Status = status, Ip = ip, CheckedAt = now };

        using var http = handler == null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        http.Timeout = TimeSpan.FromSeconds(10);
        http.MaxResponseContentBufferSize = 1024 * 1024;
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Nodar");

        try
        {
            var ip = knownPublicIp;
            if (string.IsNullOrWhiteSpace(ip))
                ip = (await http.GetStringAsync(PublicIpEndpoint, ct)).Trim();

            if (!IPAddress.TryParse(ip, out var address))
                return Result(InternetCheckStatus.Failed);
            if (!IsPublicIPv4(address))
                return Result(InternetCheckStatus.NotPublic, address.ToString());

            using var response = await http.GetAsync(new Uri(LookupBase, address.ToString()), ct);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return Result(InternetCheckStatus.NothingSeen, address.ToString()); // o Shodan não viu nada aberto
            if (!response.IsSuccessStatusCode)
                return Result(InternetCheckStatus.Failed, address.ToString());

            return Parse(await response.Content.ReadAsStringAsync(ct), address.ToString(), now);
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, "Consulta ao Shodan InternetDB", ct))
        {
            return Result(InternetCheckStatus.Failed);
        }
    }

    /// <summary>Lê a resposta do InternetDB (<c>{"ports":[…],"vulns":[…],"hostnames":[…],"tags":[…]}</c>).</summary>
    public static InternetExposure Parse(string json, string ip, DateTime now)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        List<string> Strings(string name, Func<string, bool>? accept = null) =>
            root.TryGetProperty(name, out var array) && array.ValueKind == JsonValueKind.Array
                ? array.EnumerateArray()
                    .Where(e => e.ValueKind == JsonValueKind.String)
                    .Select(e => e.GetString()!.Trim())
                    .Where(s => s.Length is > 0 and <= 120 && (accept?.Invoke(s) ?? true))
                    .Distinct().Take(MaxItems).ToList()
                : [];

        var ports = root.TryGetProperty("ports", out var portArray) && portArray.ValueKind == JsonValueKind.Array
            ? portArray.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var p) && p is >= 1 and <= 65535)
                .Select(e => e.GetInt32()).Distinct().Order().Take(MaxItems).ToList()
            : [];

        // Os CVEs viram ligações para a NVD: só se aceita o formato exato.
        var vulns = Strings("vulns", s => CvePattern().IsMatch(s));
        var seenAnything = ports.Count > 0 || vulns.Count > 0;

        return new InternetExposure
        {
            Status = seenAnything ? InternetCheckStatus.Ok : InternetCheckStatus.NothingSeen,
            Ip = ip,
            Ports = ports,
            Vulns = vulns.Order(StringComparer.Ordinal).ToList(),
            Hostnames = Strings("hostnames"),
            Tags = Strings("tags"),
            CheckedAt = now
        };
    }

    /// <summary>Endereço IPv4 alcançável na internet (nem privado, nem CGNAT, nem reservado).</summary>
    public static bool IsPublicIPv4(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return false;
        var b = address.GetAddressBytes();
        return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224
                 || (b[0] == 100 && b[1] is >= 64 and <= 127)   // 100.64.0.0/10: CGNAT
                 || (b[0] == 169 && b[1] == 254)                // link-local
                 || (b[0] == 172 && b[1] is >= 16 and <= 31)
                 || (b[0] == 192 && b[1] == 168)
                 || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                 || (b[0] == 198 && b[1] is 18 or 19));         // testes de desempenho de redes
    }

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$")]
    private static partial Regex CvePattern();
}
