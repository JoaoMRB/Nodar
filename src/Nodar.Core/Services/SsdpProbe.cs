using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Nodar.Core.Services;

/// <summary>
/// Identificação por SSDP/UPnP: Smart TVs, boxes de TV, consolas, colunas e routers anunciam-se e publicam um
/// descritor XML com nome, fabricante e modelo.
/// </summary>
/// <remarks>
/// Envia um <c>M-SEARCH</c> multicast (239.255.255.250:1900) a partir de uma porta efémera; as respostas chegam
/// por unicast. Depois lê o descritor de cada dispositivo, apenas se o endereço for da rede local, por HTTP e com
/// limites de tamanho e tempo. O XML é lido sem DTD (proteção contra XXE).
/// </remarks>
public static class SsdpProbe
{
    public sealed class Identity
    {
        public string Ip { get; init; } = "";
        public string? FriendlyName { get; set; }
        public string? Manufacturer { get; set; }
        public string? ModelName { get; set; }
        public string? ModelNumber { get; set; }
        public string? DeviceType { get; set; }
        public string? Server { get; set; }
        public string? Location { get; set; }
    }

    private static readonly IPEndPoint MulticastEndpoint = new(IPAddress.Parse("239.255.255.250"), 1900);
    private const int MaxDescriptorBytes = 256 * 1024;

    public static async Task<Dictionary<string, Identity>> QueryAsync(
        Func<string, bool> isLocal, CancellationToken ct, TimeSpan? listen = null)
    {
        var found = new Dictionary<string, Identity>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);

            var search = Encoding.ASCII.GetBytes(
                "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 1\r\n" +
                "ST: ssdp:all\r\n" +
                "USER-AGENT: Windows/10 UPnP/1.1 Nodar/1.0\r\n\r\n");

            // Duas vezes: UDP perde pacotes, sobretudo em Wi-Fi.
            await udp.SendAsync(search, MulticastEndpoint, ct);
            _ = Task.Delay(400, ct).ContinueWith(async _ => { try { await udp.SendAsync(search, MulticastEndpoint, ct); } catch { } },
                ct, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(listen ?? TimeSpan.FromSeconds(2));
            while (true)
            {
                UdpReceiveResult received;
                try { received = await udp.ReceiveAsync(timeout.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { break; }
                catch (SocketException) { continue; }

                var ip = received.RemoteEndPoint.Address.ToString();
                if (!isLocal(ip))
                    continue;
                var headers = ParseHeaders(Encoding.ASCII.GetString(received.Buffer));
                if (!found.TryGetValue(ip, out var identity))
                    found[ip] = identity = new Identity { Ip = ip };
                identity.Server ??= headers.GetValueOrDefault("SERVER");
                // Preferir o descritor do dispositivo raiz.
                if (headers.TryGetValue("LOCATION", out var location) && (identity.Location == null ||
                        headers.GetValueOrDefault("ST", "").Contains("rootdevice", StringComparison.OrdinalIgnoreCase)))
                    identity.Location = location;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
            return found;
        }

        // Ler os descritores (em paralelo, só da rede local).
        using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false })
        {
            Timeout = TimeSpan.FromSeconds(2.5),
            MaxResponseContentBufferSize = MaxDescriptorBytes
        };
        await Task.WhenAll(found.Values.Where(i => i.Location != null).Select(async identity =>
        {
            if (!Uri.TryCreate(identity.Location, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp
                || uri.Host != identity.Ip)
                return; // só o próprio dispositivo, por HTTP simples
            try
            {
                var xml = await http.GetStringAsync(uri, ct);
                ApplyDescriptor(identity, xml);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                // Descritor indisponível: fica o cabeçalho SERVER.
            }
        }));

        return found;
    }

    public static Dictionary<string, string> ParseHeaders(string response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in response.Split("\r\n").Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon > 0)
                headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
        }
        return headers;
    }

    /// <summary>Lê friendlyName, manufacturer, modelName, modelNumber e deviceType do descritor UPnP.</summary>
    public static void ApplyDescriptor(Identity identity, string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, // sem entidades externas (XXE)
            XmlResolver = null,
            MaxCharactersInDocument = MaxDescriptorBytes,
            IgnoreComments = true
        };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        var depthOfFirstDevice = -1;
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element)
                continue;
            if (reader.LocalName == "device" && depthOfFirstDevice < 0)
            {
                depthOfFirstDevice = reader.Depth;
                continue;
            }
            // Só os campos do dispositivo raiz (os sub-dispositivos repetem-nos).
            if (depthOfFirstDevice < 0 || reader.Depth != depthOfFirstDevice + 1)
                continue;

            switch (reader.LocalName)
            {
                case "friendlyName": identity.FriendlyName ??= Clean(reader.ReadElementContentAsString()); break;
                case "manufacturer": identity.Manufacturer ??= Clean(reader.ReadElementContentAsString()); break;
                case "modelName": identity.ModelName ??= Clean(reader.ReadElementContentAsString()); break;
                case "modelNumber": identity.ModelNumber ??= Clean(reader.ReadElementContentAsString()); break;
                case "deviceType": identity.DeviceType ??= Clean(reader.ReadElementContentAsString()); break;
            }
        }
    }

    private static string? Clean(string value)
    {
        var v = Regex.Replace(value, @"\s+", " ").Trim();
        return v.Length is 0 or > 120 ? null : v;
    }
}
