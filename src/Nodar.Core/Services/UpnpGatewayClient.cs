using System.Net;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Nodar.Core.Models;

namespace Nodar.Core.Services;

/// <summary>
/// Pergunta ao router (UPnP IGD) que portas abriu para a internet e qual é o seu endereço público.
/// </summary>
/// <remarks>
/// <para>O router anuncia-se por SSDP (<see cref="SsdpProbe"/>) com a localização do seu descritor XML. Dele sai o
/// endereço de controlo do serviço <c>WANIPConnection</c>, ao qual se pedem, um a um, os redirecionamentos
/// (<c>GetGenericPortMappingEntry</c>) até o router dizer que acabaram (erro 713).</para>
/// <para>São consultas anónimas e só de leitura: nunca se pede nem se altera nada, e não há credenciais. Só se fala
/// com o próprio router (o endereço de controlo tem de ser do mesmo IP que o descritor), por HTTP simples, com
/// limites de tamanho, de tempo e de número de entradas. O XML é lido sem DTD (proteção contra XXE).</para>
/// </remarks>
public static class UpnpGatewayClient
{
    /// <summary>Um router a devolver entradas sem fim não nos prende: lê-se até este limite.</summary>
    public const int MaxMappings = 256;

    private const int MaxBytes = 256 * 1024;

    /// <summary>Por ordem de preferência. Só estes tipos são aceites (também são colocados no pedido SOAP).</summary>
    private static readonly string[] WanServiceTypes =
    [
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1"
    ];

    public sealed record WanService(string ServiceType, Uri ControlUrl);

    /// <param name="gatewayIp">IP do router (o único que se contacta).</param>
    /// <param name="location">Endereço do descritor UPnP, tal como o router o anunciou por SSDP (<c>null</c> se não anunciou).</param>
    /// <param name="handler">Só para testes.</param>
    public static async Task<UpnpReport> ReadAsync(string gatewayIp, string? location, CancellationToken ct,
        HttpMessageHandler? handler = null)
    {
        if (!Uri.TryCreate(location, UriKind.Absolute, out var descriptorUri)
            || descriptorUri.Scheme != Uri.UriSchemeHttp || descriptorUri.Host != gatewayIp)
            return new UpnpReport { Status = UpnpStatus.NotFound };

        using var http = handler == null
            ? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false })
            : new HttpClient(handler, disposeHandler: false);
        http.Timeout = TimeSpan.FromSeconds(3);
        http.MaxResponseContentBufferSize = MaxBytes;

        using var overall = CancellationTokenSource.CreateLinkedTokenSource(ct);
        overall.CancelAfter(TimeSpan.FromSeconds(12));
        try
        {
            var services = ParseWanServices(await http.GetStringAsync(descriptorUri, overall.Token), descriptorUri);
            if (services.Count == 0)
                return new UpnpReport { Status = UpnpStatus.NotFound }; // não é um router com ligação WAN

            // Alguns routers têm o serviço IP e o PPP, e só um está configurado: fica o primeiro com algo útil.
            UpnpReport? first = null;
            foreach (var service in services)
            {
                var report = await ReadServiceAsync(http, service, overall.Token);
                first ??= report;
                if (report.Status == UpnpStatus.Ok && (report.Mappings.Count > 0 || report.ExternalIp != null))
                    return report;
            }
            return first!;
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, "Leitura UPnP do router", ct))
        {
            return new UpnpReport { Status = UpnpStatus.Failed };
        }
    }

    private static async Task<UpnpReport> ReadServiceAsync(HttpClient http, WanService service, CancellationToken ct)
    {
        string? externalIp = null;
        var ipReply = await SoapAsync(http, service, "GetExternalIPAddress", "", ct);
        if (ipReply.IsSuccess && ReadFields(ipReply.Body).TryGetValue("NewExternalIPAddress", out var text)
            && IPAddress.TryParse(text, out var ip) && !ip.Equals(IPAddress.Any))
            externalIp = ip.ToString();

        var mappings = new List<PortMapping>();
        var truncated = false;
        for (var index = 0; ; index++)
        {
            if (index >= MaxMappings)
            {
                truncated = true;
                break;
            }

            var reply = await SoapAsync(http, service, "GetGenericPortMappingEntry",
                $"<NewPortMappingIndex>{index}</NewPortMappingIndex>", ct);
            if (!reply.IsSuccess)
            {
                if (reply.ErrorCode is 713 or 714)
                    break; // índice fora da lista: não há mais entradas (ou nenhuma)
                if (index == 0)
                    return new UpnpReport { Status = UpnpStatus.ListingRefused, ExternalIp = externalIp };
                break;
            }

            if (ParseMapping(ReadFields(reply.Body)) is { } mapping)
                mappings.Add(mapping);
        }

        return new UpnpReport { Status = UpnpStatus.Ok, ExternalIp = externalIp, Mappings = mappings, Truncated = truncated };
    }

    // ---------------------------------------------------------------- SOAP

    private sealed record SoapReply(int Status, string Body)
    {
        public bool IsSuccess => Status is >= 200 and < 300;

        /// <summary>Código de erro UPnP de uma resposta de falha (ex.: 713 = SpecifiedArrayIndexInvalid).</summary>
        public int? ErrorCode
        {
            get
            {
                try
                {
                    return ReadFields(Body).TryGetValue("errorCode", out var code) && int.TryParse(code, out var n) ? n : null;
                }
                catch (XmlException)
                {
                    return null; // resposta de falha que nem XML é
                }
            }
        }
    }

    private static async Task<SoapReply> SoapAsync(HttpClient http, WanService service, string action, string arguments, CancellationToken ct)
    {
        var body =
            "<?xml version=\"1.0\"?>" +
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
            $"<s:Body><u:{action} xmlns:u=\"{service.ServiceType}\">{arguments}</u:{action}></s:Body></s:Envelope>";

        using var request = new HttpRequestMessage(HttpMethod.Post, service.ControlUrl)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/xml")
        };
        request.Headers.TryAddWithoutValidation("SOAPACTION", $"\"{service.ServiceType}#{action}\"");

        using var response = await http.SendAsync(request, ct);
        return new SoapReply((int)response.StatusCode, await response.Content.ReadAsStringAsync(ct));
    }

    // ---------------------------------------------------------------- Leitura do XML

    private static XDocument Load(string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, // sem entidades externas (XXE)
            XmlResolver = null,
            MaxCharactersInDocument = MaxBytes,
            IgnoreComments = true
        };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        return XDocument.Load(reader);
    }

    /// <summary>Os elementos folha de um documento, por nome local (ignora espaços de nomes e envelopes SOAP).</summary>
    public static Dictionary<string, string> ReadFields(string xml)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var element in Load(xml).Descendants().Where(e => !e.HasElements))
            fields[element.Name.LocalName] = element.Value.Trim();
        return fields;
    }

    /// <summary>Os serviços de ligação WAN do descritor, só os do próprio router, do preferido para o menos.</summary>
    public static List<WanService> ParseWanServices(string xml, Uri descriptor)
    {
        var doc = Load(xml);
        string? Child(XElement parent, string name) =>
            parent.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim();

        var urlBase = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "URLBase")?.Value.Trim();
        var baseUri = Uri.TryCreate(urlBase, UriKind.Absolute, out var parsedBase) ? parsedBase : descriptor;

        var found = new List<WanService>();
        foreach (var service in doc.Descendants().Where(e => e.Name.LocalName == "service"))
        {
            var type = Child(service, "serviceType");
            var control = Child(service, "controlURL");
            if (type == null || control == null || !WanServiceTypes.Contains(type))
                continue;
            if (!Uri.TryCreate(baseUri, control, out var url))
                continue;
            // Só o próprio router: um descritor malicioso não nos faz falar com outra máquina.
            if (url.Scheme != Uri.UriSchemeHttp || url.Host != descriptor.Host)
                continue;
            found.Add(new WanService(type, url));
        }
        return [.. found.OrderBy(s => Array.IndexOf(WanServiceTypes, s.ServiceType))];
    }

    /// <summary>Um redirecionamento a partir dos campos da resposta; <c>null</c> se estiver incompleto ou for estranho.</summary>
    public static PortMapping? ParseMapping(IReadOnlyDictionary<string, string> f)
    {
        string Get(string key) => f.GetValueOrDefault(key, "");

        if (!int.TryParse(Get("NewExternalPort"), out var external) || external is < 1 or > 65535)
            return null;
        if (!int.TryParse(Get("NewInternalPort"), out var internalPort) || internalPort is < 1 or > 65535)
            return null;
        if (!IPAddress.TryParse(Get("NewInternalClient"), out var client))
            return null;
        var protocol = Get("NewProtocol").ToUpperInvariant();
        if (protocol is not ("TCP" or "UDP"))
            return null;

        _ = int.TryParse(Get("NewLeaseDuration"), out var lease);
        return new PortMapping
        {
            Protocol = protocol,
            ExternalPort = external,
            InternalClient = client.ToString(),
            InternalPort = internalPort,
            Description = Sanitize(Get("NewPortMappingDescription")),
            Enabled = Get("NewEnabled") is "1" or "true" or "True",
            LeaseSeconds = Math.Max(lease, 0),
            RemoteHost = Sanitize(Get("NewRemoteHost"))
        };
    }

    /// <summary>O texto vem do router (e das apps que lhe pediram portas): sem controlo e com tamanho limitado.</summary>
    private static string Sanitize(string value)
    {
        var clean = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return clean.Length > 80 ? clean[..80] : clean;
    }
}
