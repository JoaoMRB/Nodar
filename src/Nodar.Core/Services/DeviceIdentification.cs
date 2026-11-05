using System.Text.RegularExpressions;

namespace Nodar.Core.Services;

/// <summary>
/// Converte o que os dispositivos anunciam por mDNS (modelo, nome, serviços) em nome, modelo, fabricante e tipo
/// legíveis. Ex.: "Mac14,7" → MacBook/Mac, Apple, Computador.
/// </summary>
public static class DeviceIdentification
{
    public sealed record Description(string? FriendlyName, string? Model, string? Vendor, string? DeviceType);

    /// <summary>
    /// Combina as três fontes. Nome: mDNS → SSDP → NetBIOS. Fabricante e modelo: mDNS → SSDP (o fabricante do
    /// descritor UPnP é mais fiável do que o do MAC, que muitas vezes é o do chip Wi-Fi).
    /// </summary>
    public static Description? Combine(MdnsProbe.Identity? mdns, SsdpProbe.Identity? ssdp, NetBiosProbe.Names? netbios)
    {
        var fromMdns = mdns != null ? Describe(mdns) : null;
        var fromSsdp = ssdp != null ? Describe(ssdp) : null;
        if (fromMdns == null && fromSsdp == null && string.IsNullOrWhiteSpace(netbios?.ComputerName))
            return null;

        return new Description(
            fromMdns?.FriendlyName ?? fromSsdp?.FriendlyName ?? netbios?.ComputerName,
            fromMdns?.Model ?? fromSsdp?.Model,
            fromSsdp?.Vendor ?? fromMdns?.Vendor,
            fromMdns?.DeviceType ?? fromSsdp?.DeviceType);
    }

    /// <summary>Descritor UPnP: "TP-Link Archer AX55" (InternetGatewayDevice) → modelo e tipo Router.</summary>
    public static Description Describe(SsdpProbe.Identity ssdp)
    {
        var manufacturer = string.IsNullOrWhiteSpace(ssdp.Manufacturer) ? null : OuiRegistry.ShortName(ssdp.Manufacturer);
        var model = ssdp.ModelName;
        if (!string.IsNullOrWhiteSpace(model) && manufacturer != null && !model.StartsWith(manufacturer, StringComparison.OrdinalIgnoreCase))
            model = $"{manufacturer} {model}";

        // O friendlyName de muitos routers/TVs é só o modelo: aí não acrescenta nada como nome.
        var friendly = ssdp.FriendlyName;
        if (friendly != null && (model?.Contains(friendly, StringComparison.OrdinalIgnoreCase) == true
                                 || friendly.Contains(ssdp.ModelName ?? "\u0000", StringComparison.OrdinalIgnoreCase)))
            friendly = null;

        var type = ssdp.DeviceType?.ToLowerInvariant() switch
        {
            null => null,
            var t when t.Contains("internetgatewaydevice") || t.Contains("wfadevice") => "Router",
            var t when t.Contains("mediarenderer") || t.Contains(":dial:") => "TV",
            var t when t.Contains("printer") => "Impressora",
            var t when t.Contains("mediaserver") => "Servidor",
            _ => null
        };
        if (type == null && ssdp.Server?.Contains("Chromecast", StringComparison.OrdinalIgnoreCase) == true)
            type = "TV";

        return new Description(friendly, model, manufacturer, type);
    }

    public static Description Describe(MdnsProbe.Identity identity)
    {
        var (model, vendor, type) = FromModelId(identity.ModelId);

        // Serviço anunciado ajuda quando o modelo é desconhecido.
        if (type == null)
        {
            if (identity.Services.Contains("_googlecast._tcp.local"))
                type = "TV";
            else if (identity.Services.Contains("_ipp._tcp.local"))
                type = "Impressora";
        }

        var friendly = identity.FriendlyName;
        if (string.IsNullOrWhiteSpace(friendly) && !string.IsNullOrWhiteSpace(identity.Hostname))
            friendly = PrettyHostname(identity.Hostname);

        // Pelo hostname .local (ex.: "IPhone-da-Ana.local") quando não há modelo.
        if (type == null && !string.IsNullOrWhiteSpace(identity.Hostname))
        {
            var host = identity.Hostname.ToLowerInvariant();
            if (host.StartsWith("iphone") || host.StartsWith("ipad")) { type = "Apple"; vendor ??= "Apple"; model ??= host.StartsWith("ipad") ? "iPad" : "iPhone"; }
            else if (host.StartsWith("macbook") || host.StartsWith("imac") || host.StartsWith("mac-mini") || host.StartsWith("mac-")) { type = "Computador"; vendor ??= "Apple"; }
        }

        return new Description(string.IsNullOrWhiteSpace(friendly) ? null : friendly.Trim(), model, vendor, type);
    }

    /// <summary>Família de produto a partir do identificador de modelo (Apple, Google Cast, impressoras).</summary>
    public static (string? Model, string? Vendor, string? Type) FromModelId(string? modelId)
    {
        if (string.IsNullOrWhiteSpace(modelId))
            return (null, null, null);
        var id = modelId.Trim();

        (string Prefix, string Name, string Type)[] apple =
        [
            ("MacBookPro", "MacBook Pro", "Computador"),
            ("MacBookAir", "MacBook Air", "Computador"),
            ("MacBook", "MacBook", "Computador"),
            ("iMac", "iMac", "Computador"),
            ("Macmini", "Mac mini", "Computador"),
            ("MacPro", "Mac Pro", "Computador"),
            ("iPhone", "iPhone", "Apple"),
            ("iPad", "iPad", "Apple"),
            ("iPod", "iPod touch", "Apple"),
            ("AppleTV", "Apple TV", "TV"),
            ("AudioAccessory", "HomePod", "Smart Home"),
            ("Watch", "Apple Watch", "Apple"),
            ("RealityDevice", "Apple Vision Pro", "Apple"),
        ];
        foreach (var (prefix, name, type) in apple)
            if (Regex.IsMatch(id, $@"^{prefix}\d+,\d+$"))
                return (name, "Apple", type);

        // Macs recentes usam "MacNN,N" para todos os modelos (MacBook, iMac, mini, Studio…).
        if (Regex.IsMatch(id, @"^Mac\d+,\d+$"))
            return ("Mac", "Apple", "Computador");

        var lower = id.ToLowerInvariant();
        if (lower.Contains("chromecast")) return ("Chromecast", "Google", "TV");
        if (lower.Contains("nest") || lower.Contains("google home")) return (id, "Google", "Smart Home");
        if (lower.StartsWith("mitv") || lower.Contains("bravia") || lower.Contains("android tv") || lower.Contains("google tv"))
            return (id, null, "TV");
        if (Regex.IsMatch(id, @"\b(EPSON|HP|Brother|Canon|Kyocera|Lexmark|Xerox|Ricoh)\b", RegexOptions.IgnoreCase))
            return (id, id.Split(' ')[0], "Impressora");

        return (id, null, null);
    }

    /// <summary>"IPhone-de-Ana-Silva.local" → "iPhone de Ana Silva"; "MacBook-Pro-da-Ana-2.local" → "MacBook Pro da Ana".</summary>
    public static string PrettyHostname(string hostname)
    {
        var name = hostname.Trim().TrimEnd('.');
        if (name.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
            name = name[..^6];
        name = Regex.Replace(name, @"-\d+$", "");      // contador de conflito de nomes do Bonjour
        name = name.Replace('-', ' ').Trim();
        name = Regex.Replace(name, @"^IPhone\b", "iPhone");
        name = Regex.Replace(name, @"^IPad\b", "iPad");
        return name;
    }

    /// <summary>Hostnames que não dizem nada (o router usa o MAC como nome, ou um UUID).</summary>
    public static bool IsMeaninglessHostname(string? hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname))
            return true;
        var first = hostname.Split('.')[0];
        return Regex.IsMatch(first, @"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
               || Regex.IsMatch(first, @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase);
    }
}
