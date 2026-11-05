using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Nodar.Core.Models;

namespace Nodar.Core.Services;

/// <summary>
/// Descoberta de dispositivos por ARP: a forma fiável de saber quem está na mesma rede local.
/// </summary>
/// <remarks>
/// <para>Um dispositivo só pode comunicar na LAN se responder a ARP, mas muitos ignoram ping
/// (iPhones bloqueados, Macs com firewall em modo furtivo, Windows com firewall, impressoras, IoT).
/// Por isso a presença é decidida apenas por ARP; o ping não é exigido.</para>
/// <para>Para ser rápido, não se pergunta endereço a endereço. Envia-se um datagrama UDP vazio para cada
/// endereço da sub-rede, o que obriga o Windows a resolver todos por ARP em paralelo, e lê-se a tabela de
/// vizinhos do sistema (<c>GetIpNetTable2</c>) alguns segundos depois. Não precisa de privilégios de
/// administrador.</para>
/// </remarks>
public static class NeighborDiscovery
{
    /// <summary>Redes até este tamanho são varridas por inteiro (/22). Maiores só com "sub-rede completa".</summary>
    public const int FullSweepLimit = 1024;
    private const int DeepSweepLimit = 65536;

    public sealed record Neighbor(string Ip, string Mac, NeighborState State);

    public enum NeighborState
    {
        Unreachable = 0, Incomplete = 1, Probe = 2, Delay = 3, Stale = 4, Reachable = 5, Permanent = 6
    }

    public sealed record Result(
        Dictionary<string, string> Devices,
        HashSet<string> Unconfirmed,
        int AddressesSwept,
        bool PartialSweep);

    public static async Task<Result> DiscoverAsync(LocalNetworkInfo network, bool deep, CancellationToken ct, TimeSpan? settle = null)
    {
        var range = HostRange(network.IpAddress, network.SubnetMask);
        var limit = deep ? DeepSweepLimit : FullSweepLimit;
        var partial = range.Count > limit;
        var targets = partial ? NearestAddresses(range, network.IpAddress, limit) : range;

        // 1. Provocar a resolução ARP de todos os endereços ao mesmo tempo.
        TriggerArp(targets, ct);

        // 2. Dar tempo ao sistema para receber as respostas.
        await Task.Delay(settle ?? TimeSpan.FromSeconds(3), ct);

        // 3. Ler a tabela de vizinhos.
        var devices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var unconfirmed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in ReadNeighborTable())
        {
            if (!IsUsable(n) || !IsInNetwork(n.Ip, network.IpAddress, network.SubnetMask) || IsBroadcastOrNetwork(n.Ip, network))
                continue;
            devices[n.Ip] = n.Mac;
            // Entradas antigas ainda não reconfirmadas: verificadas outra vez no fim do scan.
            if (n.State is NeighborState.Stale or NeighborState.Delay or NeighborState.Probe)
                unconfirmed.Add(n.Ip);
        }

        return new Result(devices, unconfirmed, targets.Count, partial);
    }

    /// <summary>
    /// Volta a ler a tabela no fim do scan e devolve os endereços não confirmados que o sistema já deu como
    /// inalcançáveis (dispositivos que saíram há pouco e ainda estavam em cache).
    /// </summary>
    public static HashSet<string> GoneSince(IEnumerable<string> unconfirmed)
    {
        var table = ReadNeighborTable().GroupBy(n => n.Ip).ToDictionary(g => g.Key, g => g.Max(n => n.State));
        return unconfirmed
            .Where(ip => !table.TryGetValue(ip, out var state) || state is NeighborState.Unreachable or NeighborState.Incomplete)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsUsable(Neighbor n) =>
        n.State is NeighborState.Reachable or NeighborState.Stale or NeighborState.Delay or NeighborState.Probe or NeighborState.Permanent
        && n.Mac != "00:00:00:00:00:00" && n.Mac != "FF:FF:FF:FF:FF:FF"
        && !n.Mac.StartsWith("01:00:5E", StringComparison.Ordinal); // multicast IPv4

    private static void TriggerArp(IEnumerable<string> targets, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var payload = Array.Empty<byte>();
        foreach (var ip in targets)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                // Porta 9 ("discard"): o conteúdo é irrelevante, só interessa a resolução ARP que provoca.
                socket.SendTo(payload, new IPEndPoint(IPAddress.Parse(ip), 9));
            }
            catch (SocketException)
            {
                // Endereço inválido para envio, ou fila cheia: o próximo scan tenta outra vez.
            }
        }
    }

    // ------------------------------------------------------------------ endereços

    public static List<string> HostRange(string ip, string mask)
    {
        var start = ToUInt(ip) & ToUInt(mask);
        var end = start | ~ToUInt(mask);
        var hosts = new List<string>();
        for (var addr = start + 1; addr < end; addr++)
            hosts.Add(FromUInt(addr));
        return hosts;
    }

    /// <summary>Em redes enormes, os <paramref name="count"/> endereços mais próximos do nosso.</summary>
    public static List<string> NearestAddresses(List<string> range, string localIp, int count)
    {
        var local = ToUInt(localIp);
        return range.OrderBy(ip => Math.Abs((long)ToUInt(ip) - local)).Take(count).ToList();
    }

    private static bool IsInNetwork(string ip, string localIp, string mask) =>
        (ToUInt(ip) & ToUInt(mask)) == (ToUInt(localIp) & ToUInt(mask));

    private static bool IsBroadcastOrNetwork(string ip, LocalNetworkInfo network)
    {
        var mask = ToUInt(network.SubnetMask);
        var addr = ToUInt(ip);
        var net = ToUInt(network.IpAddress) & mask;
        return addr == net || addr == (net | ~mask);
    }

    public static uint ToUInt(string ip)
    {
        var b = IPAddress.Parse(ip).GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string FromUInt(uint v) => $"{v >> 24}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}";

    /// <summary>Bit "localmente administrado": MAC privado/aleatório (iOS, Android, Windows, macOS).</summary>
    public static bool IsRandomizedMac(string mac)
    {
        if (string.IsNullOrWhiteSpace(mac) || mac.Length < 2)
            return false;
        return byte.TryParse(mac[..2], System.Globalization.NumberStyles.HexNumber, null, out var first) && (first & 0x02) != 0;
    }

    // ------------------------------------------------------------------ GetIpNetTable2

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr memory);

    private const ushort AF_INET = 2;
    private const int RowSize = 88;           // sizeof(MIB_IPNET_ROW2)
    private const int TableHeaderSize = 8;    // NumEntries (4) + alinhamento a 8 bytes
    private const int OffsetPhysicalAddress = 40;
    private const int OffsetPhysicalAddressLength = 72;
    private const int OffsetState = 76;

    /// <summary>Tabela de vizinhos IPv4 do Windows (equivalente a <c>Get-NetNeighbor</c>).</summary>
    public static List<Neighbor> ReadNeighborTable()
    {
        var result = new List<Neighbor>();
        if (GetIpNetTable2(AF_INET, out var table) != 0 || table == IntPtr.Zero)
            return result;

        try
        {
            var count = Marshal.ReadInt32(table);
            for (var i = 0; i < count; i++)
            {
                var row = table + TableHeaderSize + i * RowSize;

                // SOCKADDR_INET (IPv4): família em 0, endereço em 4..7
                if ((ushort)Marshal.ReadInt16(row) != AF_INET)
                    continue;
                var ipBytes = new byte[4];
                Marshal.Copy(row + 4, ipBytes, 0, 4);

                var macLength = Marshal.ReadInt32(row + OffsetPhysicalAddressLength);
                if (macLength != 6)
                    continue;
                var mac = new byte[6];
                Marshal.Copy(row + OffsetPhysicalAddress, mac, 0, 6);

                var state = (NeighborState)Marshal.ReadInt32(row + OffsetState);
                result.Add(new Neighbor(new IPAddress(ipBytes).ToString(), string.Join(":", mac.Select(b => b.ToString("X2"))), state));
            }
        }
        finally
        {
            FreeMibTable(table);
        }

        return result;
    }
}
