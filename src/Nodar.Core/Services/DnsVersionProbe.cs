using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Nodar.Core.Services;

/// <summary>
/// Pergunta a versão a um servidor DNS com a consulta <c>version.bind</c> (TXT, classe CHAOS).
/// O dnsmasq (presente em muitos routers e no Pi-hole), o Unbound e o BIND respondem com a versão,
/// a menos que tenham sido configurados para a esconder.
/// </summary>
public static class DnsVersionProbe
{
    /// <summary>Prefixo usado para guardar a resposta como "banner" do serviço DNS.</summary>
    public const string BannerPrefix = "DNS version.bind: ";

    private const ushort TypeTxt = 16;
    private const ushort ClassChaos = 3;

    public static async Task<string?> QueryAsync(string ip, CancellationToken ct, TimeSpan? timeout = null, int port = 53)
    {
        var id = (ushort)RandomNumberGenerator.GetInt32(0, ushort.MaxValue + 1);
        var query = BuildQuery(id);

        using var udp = new UdpClient(AddressFamily.InterNetwork);
        try
        {
            udp.Connect(IPAddress.Parse(ip), port);
            await udp.SendAsync(query, ct);

            using var wait = CancellationTokenSource.CreateLinkedTokenSource(ct);
            wait.CancelAfter(timeout ?? TimeSpan.FromSeconds(2));

            while (true)
            {
                var result = await udp.ReceiveAsync(wait.Token);
                var text = ParseResponse(result.Buffer, id);
                if (text != null)
                    return text;
                // Pacote que não corresponde à nossa consulta: continuar à espera.
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null; // timeout, ICMP port unreachable, etc.
        }
    }

    /// <summary>Consulta DNS: <c>version.bind. CH TXT</c>.</summary>
    public static byte[] BuildQuery(ushort id)
    {
        var name = EncodeName("version.bind");
        var packet = new byte[12 + name.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0), id);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 0x0000); // consulta normal, sem recursão
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), 1);      // QDCOUNT
        name.CopyTo(packet, 12);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(12 + name.Length), TypeTxt);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(14 + name.Length), ClassChaos);
        return packet;
    }

    /// <summary>
    /// Lê a primeira resposta TXT. Devolve <c>null</c> se o pacote não for a resposta à consulta
    /// <paramref name="expectedId"/>, se tiver erro ou se não trouxer TXT.
    /// </summary>
    public static string? ParseResponse(ReadOnlySpan<byte> packet, ushort expectedId)
    {
        try
        {
            if (packet.Length < 12)
                return null;
            if (BinaryPrimitives.ReadUInt16BigEndian(packet) != expectedId)
                return null;

            var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
            var isResponse = (flags & 0x8000) != 0;
            var rcode = flags & 0x000F;
            if (!isResponse || rcode != 0)
                return null;

            var questions = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
            var answers = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);

            var offset = 12;
            for (var i = 0; i < questions; i++)
            {
                offset = SkipName(packet, offset);
                offset += 4; // QTYPE + QCLASS
            }

            for (var i = 0; i < answers; i++)
            {
                offset = SkipName(packet, offset);
                var type = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
                var rdLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 8)..]);
                var rdata = packet.Slice(offset + 10, rdLength);
                offset += 10 + rdLength;

                if (type != TypeTxt)
                    continue;

                // TXT: uma ou mais strings com prefixo de comprimento.
                var sb = new StringBuilder();
                var p = 0;
                while (p < rdata.Length)
                {
                    var len = rdata[p];
                    sb.Append(Encoding.ASCII.GetString(rdata.Slice(p + 1, len)));
                    p += 1 + len;
                }

                var text = sb.ToString().Trim();
                return text.Length > 0 ? text : null;
            }

            return null;
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            return null; // pacote truncado ou malformado (o indexador de Span lança IndexOutOfRange)
        }
    }

    private static byte[] EncodeName(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.Add(0);
        return bytes.ToArray();
    }

    private static int SkipName(ReadOnlySpan<byte> packet, int offset)
    {
        while (true)
        {
            var len = packet[offset];
            if (len == 0)
                return offset + 1;
            if ((len & 0xC0) == 0xC0)
                return offset + 2; // ponteiro de compressão
            if ((len & 0xC0) != 0)
                throw new ArgumentOutOfRangeException(nameof(packet)); // tipo de label inválido
            offset += 1 + len;
        }
    }
}
