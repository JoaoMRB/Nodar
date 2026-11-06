using Nodar.Core.Models;

namespace Nodar.Core.Monitoring;

/// <summary>
/// Vigia o MAC que responde pelo router. Se mudar, ou o router foi trocado, ou o computador está noutra rede com
/// o mesmo endereço (192.168.1.1 é igualíssimo em todo o lado), ou alguém na rede está a fazer-se passar por ele
/// (ARP spoofing) para ver ou alterar o tráfego.
/// </summary>
/// <remarks>
/// <para>Por cada endereço de router guardam-se os MACs de confiança. O primeiro visto é aceite sem alerta (é a
/// linha de base); a partir daí, um MAC novo gera um alerta até o utilizador o aceitar com <see cref="Trust"/>.</para>
/// <para>A mudança sozinha é um sinal fraco. Se além disso <em>outro dispositivo da rede tem exatamente esse MAC</em>,
/// é o rasto típico do ataque (o atacante responde pelo router com a sua própria placa, que continua visível
/// com o seu IP) e o alerta passa a forte.</para>
/// </remarks>
public sealed class GatewayGuard
{
    private const int MaxMacsPerGateway = 8;

    private readonly string _path;
    private Dictionary<string, List<string>> _trusted = new(StringComparer.OrdinalIgnoreCase);

    public GatewayGuard(string dataDirectory) => _path = Path.Combine(dataDirectory, "gateway.json");

    public void Load() =>
        _trusted = new Dictionary<string, List<string>>(
            JsonStore.Read<Dictionary<string, List<string>>>(_path) ?? [], StringComparer.OrdinalIgnoreCase);

    /// <summary>MACs de confiança de um router (para testes e para mostrar ao utilizador).</summary>
    public IReadOnlyList<string> TrustedMacs(string gatewayIp) =>
        _trusted.TryGetValue(gatewayIp, out var macs) ? macs : [];

    /// <summary>Compara o MAC do router neste scan com os conhecidos. <c>null</c> = tudo como esperado.</summary>
    public GatewayAlert? Evaluate(string gatewayIp, IReadOnlyList<DeviceInfo> devices)
    {
        var gateway = devices.FirstOrDefault(d => d.IpAddress == gatewayIp);
        if (gateway == null || MacOf(gateway) is not { } mac)
            return null; // sem MAC não há nada a comparar

        if (!_trusted.TryGetValue(gatewayIp, out var known) || known.Count == 0)
        {
            Trust(gatewayIp, mac); // primeira vez que se vê este router: linha de base
            return null;
        }
        if (known.Contains(mac, StringComparer.OrdinalIgnoreCase))
            return null;

        var twin = devices.FirstOrDefault(d => d.IpAddress != gatewayIp && MacOf(d) == mac);
        return new GatewayAlert(gatewayIp, known[^1], mac, twin?.IpAddress);
    }

    /// <summary>O utilizador confirma que este MAC é do router (trocou de router, ou está noutra rede).</summary>
    public void Trust(string gatewayIp, string mac)
    {
        var normalized = DeviceTracker.KeyFor(mac, null);
        if (normalized.StartsWith("ip:", StringComparison.Ordinal))
            return;

        if (!_trusted.TryGetValue(gatewayIp, out var macs))
            _trusted[gatewayIp] = macs = [];
        macs.RemoveAll(m => string.Equals(m, normalized, StringComparison.OrdinalIgnoreCase));
        macs.Add(normalized); // o último é o mais recente
        if (macs.Count > MaxMacsPerGateway)
            macs.RemoveAt(0);

        JsonStore.Write(_path, _trusted);
    }

    private static string? MacOf(DeviceInfo device)
    {
        var key = DeviceTracker.KeyFor(device.MacAddress, null);
        return key.StartsWith("ip:", StringComparison.Ordinal) ? null : key;
    }
}
