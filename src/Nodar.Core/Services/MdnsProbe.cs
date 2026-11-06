using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Nodar.Core.Services;

/// <summary>
/// Identificação por mDNS/Bonjour (RFC 6762/6763): nome e modelo de Macs, iPhones, iPads, Apple TV,
/// HomePod, Chromecast, impressoras…, que com MAC privado não se identificam pelo fabricante.
/// </summary>
/// <remarks>
/// As perguntas saem de uma porta efémera (não da 5353). Pela RFC 6762 §6.7 ("legacy unicast"), os
/// dispositivos respondem diretamente a essa porta, por isso não é preciso partilhar a porta 5353 com o
/// Windows nem ter privilégios de administrador.
/// </remarks>
public static class MdnsProbe
{
    public sealed class Identity
    {
        public string Ip { get; init; } = "";
        /// <summary>Nome dado pelo utilizador, ex.: "MacBook Pro do João".</summary>
        public string? FriendlyName { get; set; }
        /// <summary>Nome na rede local, ex.: "MacBook-Pro-do-Joao.local".</summary>
        public string? Hostname { get; set; }
        /// <summary>Identificador de modelo, ex.: "MacBookPro18,3", "iPhone15,2", "Chromecast".</summary>
        public string? ModelId { get; set; }
        public HashSet<string> Services { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private static readonly IPEndPoint MulticastEndpoint = new(IPAddress.Parse("224.0.0.251"), 5353);

    /// <summary>Tipos de serviço perguntados (os que anunciam nome e modelo).</summary>
    public static readonly string[] ServiceTypes =
    [
        "_device-info._tcp.local",     // Macs e outros Apple: TXT model=MacBookPro18,3
        "_companion-link._tcp.local",  // iPhone, iPad, Mac, Apple TV: TXT rpMd=iPhone15,2
        "_airplay._tcp.local",         // Apple TV, HomePod, TVs com AirPlay: TXT model=…
        "_googlecast._tcp.local",      // Chromecast, Google TV, Nest: TXT md=… fn=…
        "_ipp._tcp.local",             // Impressoras: TXT ty=…
    ];

    private const ushort TypeA = 1, TypePtr = 12, TypeTxt = 16, TypeSrv = 33;
    private const ushort ClassIn = 1;

    public static async Task<Dictionary<string, Identity>> QueryAsync(
        IReadOnlyCollection<string> knownIps, CancellationToken ct, TimeSpan? listen = null)
    {
        var identities = new Dictionary<string, Identity>(StringComparer.OrdinalIgnoreCase);
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        try
        {
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);

            async Task SendQueriesAsync()
            {
                // 1. Pergunta multicast pelos serviços que anunciam nome e modelo.
                var browse = BuildQuery(0, ServiceTypes.Select(s => (s, TypePtr)));
                await udp.SendAsync(browse, MulticastEndpoint, ct);

                // 2. Pergunta direta a cada dispositivo pelo seu nome .local (PTR inverso).
                foreach (var ip in knownIps)
                {
                    try
                    {
                        var reverse = BuildQuery(0, [(ReverseName(ip), TypePtr)]);
                        await udp.SendAsync(reverse, new IPEndPoint(IPAddress.Parse(ip), 5353), ct);
                    }
                    catch (SocketException)
                    {
                        // Endereço inalcançável: ignorar.
                    }
                }
            }

            // UDP pode perder pacotes (sobretudo em Wi-Fi): perguntar duas vezes, como recomenda a RFC 6762.
            await SendQueriesAsync();
            _ = Task.Delay(500, ct).ContinueWith(async _ => { try { await SendQueriesAsync(); } catch (Exception ex) when (NodarLog.Swallow(ex, "mDNS: segundo envio")) { } },
                ct, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);

            // 3. Recolher respostas durante o tempo de escuta.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(listen ?? TimeSpan.FromSeconds(2));
            while (true)
            {
                UdpReceiveResult received;
                try
                {
                    received = await udp.ReceiveAsync(timeout.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException)
                {
                    continue; // ex.: ICMP "port unreachable" de dispositivos sem mDNS
                }

                Merge(identities, ParseResponse(received.Buffer, received.RemoteEndPoint.Address.ToString()));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
            // Sem multicast disponível (ex.: VPN): devolve o que tiver.
        }

        return identities;
    }

    // ================================================================ construção

    public static byte[] BuildQuery(ushort id, IEnumerable<(string Name, ushort Type)> questions)
    {
        var list = questions.ToList();
        var bytes = new List<byte>(512);
        void U16(ushort v) { bytes.Add((byte)(v >> 8)); bytes.Add((byte)v); }

        U16(id);
        U16(0);                 // consulta normal
        U16((ushort)list.Count);
        U16(0); U16(0); U16(0);
        foreach (var (name, type) in list)
        {
            foreach (var label in name.TrimEnd('.').Split('.'))
            {
                var data = Encoding.UTF8.GetBytes(label);
                bytes.Add((byte)data.Length);
                bytes.AddRange(data);
            }
            bytes.Add(0);
            U16(type);
            U16(ClassIn);
        }
        return bytes.ToArray();
    }

    public static string ReverseName(string ip)
    {
        var parts = ip.Split('.');
        return $"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa";
    }

    // ================================================================ leitura

    /// <summary>Lê uma resposta mDNS e devolve identidades por IP.</summary>
    public static List<Identity> ParseResponse(byte[] packet, string sourceIp)
    {
        var records = ParseRecords(packet);
        if (records.Count == 0)
            return [];

        // Mapas dentro do pacote: instância → anfitrião (SRV), anfitrião → IP (A).
        var hostOfInstance = records.Where(r => r.Type == TypeSrv && r.Target != null)
            .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Target!, StringComparer.OrdinalIgnoreCase);
        var ipOfHost = records.Where(r => r.Type == TypeA && r.Address != null)
            .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Address!, StringComparer.OrdinalIgnoreCase);

        var result = new Dictionary<string, Identity>(StringComparer.OrdinalIgnoreCase);
        Identity For(string ip) => result.TryGetValue(ip, out var id) ? id : result[ip] = new Identity { Ip = ip };

        // Atribui a instância ao IP certo: via SRV+A (respostas de "sleep proxy" vêm de outro IP), senão a origem.
        string IpOfInstance(string instance) =>
            hostOfInstance.TryGetValue(instance, out var host) && ipOfHost.TryGetValue(host, out var ip) ? ip : sourceIp;

        foreach (var r in records)
        {
            switch (r.Type)
            {
                case TypePtr when r.Target != null && r.Name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase):
                {
                    var ip = IpFromReverse(r.Name) ?? sourceIp;
                    For(ip).Hostname ??= r.Target;
                    break;
                }
                case TypePtr when r.Target != null:
                {
                    var serviceType = ServiceTypes.FirstOrDefault(s => r.Name.Equals(s, StringComparison.OrdinalIgnoreCase));
                    if (serviceType == null)
                        break;
                    var identity = For(IpOfInstance(r.Target));
                    identity.Services.Add(serviceType);
                    var instance = InstanceName(r.Target, serviceType);
                    // No Chromecast o nome da instância é técnico ("MiTV-X1-<uuid>"): o nome real vem no TXT fn=.
                    if (!string.IsNullOrWhiteSpace(instance) && serviceType is not ("_companion-link._tcp.local" or "_googlecast._tcp.local"))
                        identity.FriendlyName ??= CleanInstanceName(instance);
                    break;
                }
                case TypeTxt when r.Txt != null:
                {
                    var identity = For(IpOfInstance(r.Name));
                    var model = Value(r.Txt, "model") ?? Value(r.Txt, "rpMd") ?? Value(r.Txt, "md") ?? Value(r.Txt, "ty");
                    if (!string.IsNullOrWhiteSpace(model))
                        identity.ModelId ??= model;
                    var friendly = Value(r.Txt, "fn");
                    if (!string.IsNullOrWhiteSpace(friendly))
                        identity.FriendlyName = friendly; // nome dado pelo utilizador: tem prioridade
                    break;
                }
                case TypeSrv when r.Target != null:
                    For(IpOfInstance(r.Name)).Hostname ??= r.Target;
                    break;
            }
        }

        // Endereços próprios anunciados (A) dizem o hostname desse IP.
        foreach (var (host, ip) in ipOfHost)
            For(ip).Hostname ??= host;

        return result.Values.ToList();
    }

    private static void Merge(Dictionary<string, Identity> into, List<Identity> found)
    {
        foreach (var f in found)
        {
            if (!into.TryGetValue(f.Ip, out var existing))
            {
                into[f.Ip] = f;
                continue;
            }
            existing.FriendlyName ??= f.FriendlyName;
            existing.Hostname ??= f.Hostname;
            existing.ModelId ??= f.ModelId;
            existing.Services.UnionWith(f.Services);
        }
    }

    private static string? Value(List<string> txt, string key)
    {
        foreach (var entry in txt)
        {
            var eq = entry.IndexOf('=');
            if (eq > 0 && entry[..eq].Equals(key, StringComparison.OrdinalIgnoreCase))
                return entry[(eq + 1)..].Trim();
        }
        return null;
    }

    private static string InstanceName(string fullName, string serviceType) =>
        fullName.EndsWith("." + serviceType, StringComparison.OrdinalIgnoreCase)
            ? fullName[..^(serviceType.Length + 1)]
            : fullName.Split('.')[0];

    /// <summary>Remove sufixos técnicos ("Sala (2)", "XXXXXXXXXXXX@Nome" do AirPlay/RAOP).</summary>
    private static string CleanInstanceName(string name)
    {
        var at = name.IndexOf('@');
        if (at > 0 && at < name.Length - 1)
            name = name[(at + 1)..];
        return name.Trim();
    }

    private static string? IpFromReverse(string name)
    {
        var parts = name.Split('.');
        return parts.Length >= 6 && parts.Take(4).All(p => byte.TryParse(p, out _))
            ? $"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}"
            : null;
    }

    public sealed record Record(string Name, ushort Type, string? Target, string? Address, List<string>? Txt);

    public static List<Record> ParseRecords(ReadOnlySpan<byte> packet)
    {
        var records = new List<Record>();
        try
        {
            if (packet.Length < 12)
                return records;
            var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
            if ((flags & 0x8000) == 0)
                return records; // é uma pergunta, não uma resposta

            var qd = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
            var total = BinaryPrimitives.ReadUInt16BigEndian(packet[6..])
                        + BinaryPrimitives.ReadUInt16BigEndian(packet[8..])
                        + BinaryPrimitives.ReadUInt16BigEndian(packet[10..]);

            var offset = 12;
            for (var i = 0; i < qd; i++)
            {
                ReadName(packet, ref offset);
                offset += 4;
            }

            for (var i = 0; i < total; i++)
            {
                var name = ReadName(packet, ref offset);
                var type = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
                var rdLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 8)..]);
                var rdStart = offset + 10;
                if (rdStart + rdLength > packet.Length)
                    break;
                offset = rdStart + rdLength;

                switch (type)
                {
                    case TypePtr:
                    {
                        var p = rdStart;
                        records.Add(new Record(name, type, ReadName(packet, ref p), null, null));
                        break;
                    }
                    case TypeSrv when rdLength > 6:
                    {
                        var p = rdStart + 6; // prioridade, peso, porta
                        records.Add(new Record(name, type, ReadName(packet, ref p), null, null));
                        break;
                    }
                    case TypeA when rdLength == 4:
                        records.Add(new Record(name, type, null, new IPAddress(packet.Slice(rdStart, 4)).ToString(), null));
                        break;
                    case TypeTxt:
                    {
                        var txt = new List<string>();
                        var p = rdStart;
                        while (p < rdStart + rdLength)
                        {
                            var len = packet[p];
                            if (p + 1 + len > rdStart + rdLength) break;
                            txt.Add(Encoding.UTF8.GetString(packet.Slice(p + 1, len)));
                            p += 1 + len;
                        }
                        records.Add(new Record(name, type, null, null, txt));
                        break;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException or ArgumentException)
        {
            // Pacote truncado ou malformado: devolve o que já leu.
        }
        return records;
    }

    /// <summary>Lê um nome DNS com suporte a compressão (ponteiros 0xC0).</summary>
    public static string ReadName(ReadOnlySpan<byte> packet, ref int offset)
    {
        var labels = new List<string>();
        var position = offset;
        var jumped = false;
        var guard = 0;

        while (true)
        {
            if (++guard > 128)
                throw new ArgumentException("Nome DNS com ciclo de ponteiros.");
            var len = packet[position];
            if (len == 0)
            {
                position++;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                var pointer = ((len & 0x3F) << 8) | packet[position + 1];
                if (!jumped)
                    offset = position + 2;
                jumped = true;
                position = pointer;
                continue;
            }
            labels.Add(Encoding.UTF8.GetString(packet.Slice(position + 1, len)));
            position += 1 + len;
        }

        if (!jumped)
            offset = position;
        return string.Join(".", labels);
    }
}
