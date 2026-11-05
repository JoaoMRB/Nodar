using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Nodar.Core.Services;

/// <summary>
/// Nome NetBIOS de PCs Windows (e de NAS/Samba): pedido "Node Status" (RFC 1002 §4.2.17) para UDP 137.
/// </summary>
public static class NetBiosProbe
{
    public sealed record Names(string Ip, string? ComputerName, string? Workgroup);

    public static async Task<Dictionary<string, Names>> QueryAsync(IReadOnlyCollection<string> ips, CancellationToken ct, TimeSpan? listen = null)
    {
        var result = new Dictionary<string, Names>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            var id = (ushort)RandomNumberGenerator.GetInt32(0, ushort.MaxValue + 1);
            var request = BuildNodeStatusRequest(id);
            foreach (var ip in ips)
            {
                try { await udp.SendAsync(request, new IPEndPoint(IPAddress.Parse(ip), 137), ct); }
                catch (SocketException) { }
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(listen ?? TimeSpan.FromSeconds(1.5));
            while (true)
            {
                UdpReceiveResult received;
                try { received = await udp.ReceiveAsync(timeout.Token); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { break; }
                catch (SocketException) { continue; } // ICMP "port unreachable" de quem não tem NetBIOS

                var names = ParseNodeStatus(received.Buffer, id, received.RemoteEndPoint.Address.ToString());
                if (names != null)
                    result[names.Ip] = names;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
            // Sem UDP disponível: sem nomes NetBIOS.
        }
        return result;
    }

    /// <summary>Pedido NBSTAT para o nome "*" (codificação de primeiro nível, RFC 1001 §14.1).</summary>
    public static byte[] BuildNodeStatusRequest(ushort id)
    {
        var packet = new byte[50];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0), id);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), 1); // QDCOUNT
        packet[12] = 32;
        var name = new byte[16];
        name[0] = (byte)'*'; // restantes a 0
        for (var i = 0; i < 16; i++)
        {
            packet[13 + 2 * i] = (byte)('A' + (name[i] >> 4));
            packet[14 + 2 * i] = (byte)('A' + (name[i] & 0x0F));
        }
        packet[45] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(46), 0x0021); // NBSTAT
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(48), 0x0001); // IN
        return packet;
    }

    /// <summary>Lê a resposta: o primeiro nome único com sufixo 0x00 é o do computador; o de grupo é o workgroup.</summary>
    public static Names? ParseNodeStatus(ReadOnlySpan<byte> packet, ushort expectedId, string sourceIp)
    {
        try
        {
            if (packet.Length < 57 || BinaryPrimitives.ReadUInt16BigEndian(packet) != expectedId)
                return null;
            if ((BinaryPrimitives.ReadUInt16BigEndian(packet[2..]) & 0x8000) == 0)
                return null;

            // Nome da resposta (34 bytes codificados) + tipo/classe/TTL/rdlength = 56; depois o número de nomes.
            var offset = 12 + 34 + 2 + 2 + 4 + 2;
            var count = packet[offset];
            offset++;

            string? computer = null, workgroup = null;
            for (var i = 0; i < count; i++)
            {
                if (offset + 18 > packet.Length)
                    break;
                var raw = Encoding.ASCII.GetString(packet.Slice(offset, 15)).TrimEnd(' ', '\0');
                var suffix = packet[offset + 15];
                var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 16)..]);
                var isGroup = (flags & 0x8000) != 0;
                offset += 18;

                if (suffix != 0x00 || raw.Length == 0 || raw.Contains('\u0001'))
                    continue;
                if (isGroup) workgroup ??= raw;
                else computer ??= raw;
            }

            return computer == null && workgroup == null ? null : new Names(sourceIp, computer, workgroup);
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
