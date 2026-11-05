using System.Text;
using Nodar.Core.Models;
using Nodar.Core.Localization;
using static Nodar.Core.Localization.Loc;

namespace Nodar.Core.Services;

public static class ExportService
{
    public static void ExportToCsv(IEnumerable<DeviceInfo> devices, string filePath)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", new[]
        {
            "IP", "MAC", T("csv.name"), "Hostname", T("csv.vendor"), T("csv.model"), T("csv.type"),
            T("csv.status"), T("csv.ports"), T("csv.thisPc"), T("csv.lastSeen")
        }.Select(Escape)));

        foreach (var d in devices)
        {
            sb.AppendLine(string.Join(",",
                Escape(d.IpAddress),
                Escape(d.MacAddress),
                Escape(d.DisplayName),
                Escape(d.Hostname),
                Escape(VendorText(d.Vendor)),
                Escape(d.Model),
                Escape(Loc.DeviceType(d.DeviceType)),
                Escape(d.Status),
                Escape(d.OpenPorts),
                d.IsLocalDevice ? T("csv.yes") : T("csv.no"),
                d.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")));
        }

        File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
    }

    /// <summary>Fabricantes "sentinela" do Core traduzidos (desconhecido, endereço privado).</summary>
    public static string VendorText(string? vendor) =>
        string.IsNullOrWhiteSpace(vendor) || vendor is "Desconhecido" or "Router/Gateway" ? T("vendor.unknown")
        : vendor == VendorService.PrivateAddressVendor ? T("vendor.private")
        : vendor;

    private static string Escape(string? value)
    {
        value ??= "";
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }
}
