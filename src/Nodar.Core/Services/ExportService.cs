using System.Text;
using Nodar.Core.Models;

namespace Nodar.Core.Services;

public static class ExportService
{
    public static void ExportToCsv(IEnumerable<DeviceInfo> devices, string filePath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("IP,MAC,Hostname,Fabricante,Tipo,Estado,Portas,Este PC,Última vez visto");

        foreach (var d in devices)
        {
            sb.AppendLine(string.Join(",",
                Escape(d.IpAddress),
                Escape(d.MacAddress),
                Escape(d.Hostname),
                Escape(d.Vendor),
                Escape(d.DeviceType),
                Escape(d.Status),
                Escape(d.OpenPorts),
                d.IsLocalDevice ? "Sim" : "Não",
                d.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")));
        }

        File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
    }

    private static string Escape(string value)
    {
        if (value.Contains(',') || value.Contains('"'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }
}
