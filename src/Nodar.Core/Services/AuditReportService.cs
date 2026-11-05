using System.Text;
using System.Text.Json;
using Nodar.Core.Localization;
using Nodar.Core.Models;
using static Nodar.Core.Localization.Loc;

namespace Nodar.Core.Services;

/// <summary>Relatórios de auditoria (HTML, Markdown, JSON) no idioma atual da app.</summary>
public static class AuditReportService
{
    /// <summary>
    /// Escapa texto para HTML. Banners, hostnames e descrições vêm da rede ou de fontes externas e
    /// nunca podem ser inseridos no relatório sem escape (injeção de HTML/JavaScript).
    /// </summary>
    private static string H(string? value) => System.Net.WebUtility.HtmlEncode(value ?? "");

    /// <summary>Texto seguro para uma célula de tabela Markdown (sem quebras de linha nem barras verticais).</summary>
    private static string MdCell(string? value) =>
        (value ?? "").Replace("\r", " ").Replace("\n", " ").Replace("|", "\\|");

    private static string CvssText(VulnerabilityInfo v) =>
        v.CvssScore.HasValue ? $"{v.CvssScore.Value.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture)} (v{v.CvssVersion})" : "—";

    private static string Severity(string severity) =>
        severity is "Critical" or "High" or "Medium" or "Low" or "None" ? T("severity." + severity) : T("severity.Unknown");

    private static string Kev(VulnerabilityInfo v) =>
        !v.IsKnownExploited ? "—" : v.KnownRansomwareUse ? T("report.kev.ransomware") : T("report.kev.yes");

    private static string Status(string status) => status == "Online" ? T("status.online") : T("status.offline");

    private static string Dash(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;

    private static string Timestamp(DateTime when) => when.ToString("G", Instance.Culture);

    public class AuditReportOptions
    {
        public bool IncludeVulnerabilities { get; set; } = true;
        public bool IncludeServices { get; set; } = true;
        public bool IncludeOSInfo { get; set; } = true;
        public bool IncludeHistory { get; set; } = true;
        public string AuditorName { get; set; } = "";
        public string Notes { get; set; } = "";
    }

    // ================================================================ HTML

    public static Task<string> GenerateHTMLReportAsync(ScanResult scanResult, Dictionary<string, DeviceHistoryEntry> history, AuditReportOptions options)
    {
        var sb = new StringBuilder();
        var now = DateTime.Now;

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html lang='{Instance.Language}'>");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset='UTF-8'>");
        sb.AppendLine($"<title>{H(T("report.title"))}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }");
        sb.AppendLine(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }");
        sb.AppendLine("h1 { color: #2c3e50; border-bottom: 3px solid #7c6cff; padding-bottom: 10px; }");
        sb.AppendLine("h2 { color: #34495e; margin-top: 30px; }");
        sb.AppendLine(".header { display: flex; flex-wrap: wrap; gap: 24px; margin-bottom: 30px; }");
        sb.AppendLine(".info-box { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }");
        sb.AppendLine("table { width: 100%; border-collapse: collapse; margin: 20px 0; }");
        sb.AppendLine("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; vertical-align: top; }");
        sb.AppendLine("th { background: #4c5bd4; color: white; }");
        sb.AppendLine("tr:hover { background: #f5f5f5; }");
        sb.AppendLine(".severity-critical { color: #e74c3c; font-weight: bold; }");
        sb.AppendLine(".severity-high { color: #e67e22; font-weight: bold; }");
        sb.AppendLine(".severity-medium { color: #f39c12; font-weight: bold; }");
        sb.AppendLine(".severity-low { color: #27ae60; font-weight: bold; }");
        sb.AppendLine(".status-online { color: #27ae60; font-weight: bold; }");
        sb.AppendLine(".status-offline { color: #e74c3c; font-weight: bold; }");
        sb.AppendLine(".summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin: 20px 0; }");
        sb.AppendLine(".summary-card { background: #4c5bd4; color: white; padding: 20px; border-radius: 5px; text-align: center; }");
        sb.AppendLine(".summary-card h3 { margin: 0; font-size: 2em; }");
        sb.AppendLine(".summary-card p { margin: 5px 0 0 0; opacity: 0.9; }");
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("<div class='container'>");

        sb.AppendLine($"<h1>🔒 {H(T("report.title"))}</h1>");
        sb.AppendLine("<div class='header'>");
        sb.AppendLine($"<div><strong>{H(T("report.date"))}:</strong> {H(Timestamp(now))}</div>");
        sb.AppendLine($"<div><strong>{H(T("report.duration"))}:</strong> {scanResult.Duration.TotalSeconds.ToString("F1", Instance.Culture)} s</div>");
        sb.AppendLine($"<div><strong>{H(T("report.method"))}:</strong> {H(scanResult.ScanMethod)}</div>");
        if (!string.IsNullOrEmpty(options.AuditorName))
            sb.AppendLine($"<div><strong>{H(T("report.auditor"))}:</strong> {H(options.AuditorName)}</div>");
        sb.AppendLine("</div>");

        if (scanResult.Network is { } net)
        {
            sb.AppendLine($"<h2>📡 {H(T("report.network"))}</h2>");
            sb.AppendLine("<div class='info-box'>");
            sb.AppendLine($"<strong>{H(T("report.localIp"))}:</strong> {H(net.IpAddress)}<br>");
            sb.AppendLine($"<strong>{H(T("report.mask"))}:</strong> {H(net.SubnetMask)}<br>");
            sb.AppendLine($"<strong>{H(T("net.network"))}:</strong> {H(net.NetworkRange)}<br>");
            sb.AppendLine($"<strong>Gateway:</strong> {H(net.Gateway)}<br>");
            sb.AppendLine($"<strong>Hostname:</strong> {H(net.Hostname)}<br>");
            sb.AppendLine($"<strong>{H(T("report.interface"))}:</strong> {H(net.InterfaceName)}");
            sb.AppendLine("</div>");
        }

        var totalVulns = scanResult.Devices.Sum(d => d.Vulnerabilities.Count);
        var criticalVulns = scanResult.Devices.Sum(d => d.Vulnerabilities.Count(v => v.Severity == "Critical"));
        var offline = history.Count(h => h.Value.Status == "Offline");

        sb.AppendLine($"<h2>📊 {H(T("report.summary"))}</h2>");
        sb.AppendLine("<div class='summary'>");
        sb.AppendLine($"<div class='summary-card'><h3>{scanResult.Devices.Count}</h3><p>{H(T("nav.devices"))}</p></div>");
        sb.AppendLine($"<div class='summary-card' style='background: #27ae60;'><h3>{scanResult.Devices.Count(d => d.Status == "Online")}</h3><p>{H(T("status.online"))}</p></div>");
        sb.AppendLine($"<div class='summary-card' style='background: #7f8c8d;'><h3>{offline}</h3><p>{H(T("status.offline"))}</p></div>");
        sb.AppendLine($"<div class='summary-card' style='background: #e67e22;'><h3>{totalVulns}</h3><p>{H(T("options.vulns"))}</p></div>");
        if (criticalVulns > 0)
            sb.AppendLine($"<div class='summary-card' style='background: #c0392b;'><h3>{criticalVulns}</h3><p>{H(T("security.critical"))}</p></div>");
        sb.AppendLine("</div>");

        if (options.IncludeVulnerabilities && totalVulns > 0)
        {
            sb.AppendLine($"<h2>⚠️ {H(T("report.vulns"))}</h2>");
            sb.AppendLine($"<p><em>{H(T("report.disclaimer"))}</em></p>");
            if (!string.IsNullOrEmpty(scanResult.VulnerabilitySourceNote))
                sb.AppendLine($"<p><em>{H(scanResult.VulnerabilitySourceNote)}</em></p>");
            sb.AppendLine("<table>");
            sb.AppendLine($"<tr><th>{H(T("report.col.device"))}</th><th>{H(T("report.col.service"))}</th><th>{H(T("report.col.severity"))}</th><th>CVSS</th><th>CVE</th><th>{H(T("report.col.kev"))}</th><th>{H(T("report.col.description"))}</th></tr>");

            foreach (var device in scanResult.Devices.Where(d => d.Vulnerabilities.Count > 0))
            {
                foreach (var vuln in device.Vulnerabilities)
                {
                    var severityClass = vuln.Severity.ToLowerInvariant() switch
                    {
                        "critical" => "severity-critical",
                        "high" => "severity-high",
                        "medium" => "severity-medium",
                        _ => "severity-low"
                    };
                    var backport = vuln.MayBeBackported ? $" <small>({H(T("report.backport"))})</small>" : "";

                    sb.AppendLine("<tr>");
                    sb.AppendLine($"<td>{H(device.DisplayName)} ({H(device.IpAddress)})</td>");
                    sb.AppendLine($"<td>{H(F("vuln.where", vuln.Product, vuln.DetectedVersion, vuln.Port))}{backport}</td>");
                    sb.AppendLine($"<td class='{severityClass}'>{H(Severity(vuln.Severity))}</td>");
                    sb.AppendLine($"<td>{H(CvssText(vuln))}</td>");
                    sb.AppendLine($"<td><a href='{H(vuln.Url)}'>{H(vuln.CVE)}</a></td>");
                    sb.AppendLine($"<td>{H(Kev(vuln))}</td>");
                    sb.AppendLine($"<td>{H(vuln.Description)}</td>");
                    sb.AppendLine("</tr>");
                }
            }
            sb.AppendLine("</table>");
        }

        sb.AppendLine($"<h2>🖥️ {H(T("report.devices"))}</h2>");
        sb.AppendLine("<table>");
        sb.Append($"<tr><th>IP</th><th>MAC</th><th>{H(T("csv.name"))}</th><th>{H(T("details.vendor"))}</th><th>{H(T("details.model"))}</th><th>{H(T("details.os"))}</th><th>{H(T("csv.type"))}</th><th>{H(T("csv.status"))}</th>");
        if (options.IncludeServices) sb.Append($"<th>{H(T("report.col.services"))}</th>");
        if (options.IncludeVulnerabilities) sb.Append("<th>CVE</th>");
        sb.AppendLine("</tr>");

        foreach (var device in scanResult.Devices)
        {
            var statusClass = device.Status == "Online" ? "status-online" : "status-offline";
            var osInfo = options.IncludeOSInfo && !string.IsNullOrEmpty(device.OperatingSystem)
                ? $"{device.OperatingSystem} ({device.OSConfidence})" : "—";

            sb.AppendLine("<tr>");
            sb.AppendLine($"<td>{H(device.IpAddress)}</td>");
            sb.AppendLine($"<td>{H(device.MacAddress)}</td>");
            sb.AppendLine($"<td>{H(device.DisplayName)}</td>");
            sb.AppendLine($"<td>{H(ExportService.VendorText(device.Vendor))}</td>");
            sb.AppendLine($"<td>{H(Dash(device.Model))}</td>");
            sb.AppendLine($"<td>{H(osInfo)}</td>");
            sb.AppendLine($"<td>{H(Loc.DeviceType(device.DeviceType))}</td>");
            sb.AppendLine($"<td class='{statusClass}'>{H(Status(device.Status))}</td>");

            if (options.IncludeServices)
            {
                var servicesList = device.Services.Count > 0
                    ? string.Join("<br>", device.Services.Select(s => H($"{s.Port} · {s.Service} {s.Product} {s.Version}".Trim())))
                    : "—";
                sb.AppendLine($"<td>{servicesList}</td>");
            }

            if (options.IncludeVulnerabilities)
            {
                var count = device.Vulnerabilities.Count;
                sb.AppendLine(count > 0 ? $"<td><span class='severity-high'>{count}</span></td>" : "<td>—</td>");
            }
            sb.AppendLine("</tr>");
        }
        sb.AppendLine("</table>");

        if (options.IncludeHistory && history.Count > 0)
        {
            sb.AppendLine($"<h2>📜 {H(T("report.history"))}</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine($"<tr><th>IP</th><th>{H(T("csv.name"))}</th><th>{H(T("details.firstSeen"))}</th><th>{H(T("csv.lastSeen"))}</th><th>{H(T("csv.status"))}</th><th>{H(T("report.col.events"))}</th></tr>");
            foreach (var entry in history.Values.OrderByDescending(h => h.SeenAt))
            {
                var lastSeen = entry.Status == "Offline" && entry.LastLeftAt.HasValue ? entry.LastLeftAt.Value : entry.SeenAt;
                var name = !string.IsNullOrWhiteSpace(entry.FriendlyName) ? entry.FriendlyName : Dash(entry.Hostname);
                sb.AppendLine("<tr>");
                sb.AppendLine($"<td>{H(entry.IpAddress)}</td>");
                sb.AppendLine($"<td>{H(name)}</td>");
                sb.AppendLine($"<td>{H(entry.FirstSeenAt is { } f ? Timestamp(f) : "—")}</td>");
                sb.AppendLine($"<td>{H(Timestamp(lastSeen))}</td>");
                sb.AppendLine($"<td class='{(entry.Status == "Online" ? "status-online" : "status-offline")}'>{H(Status(entry.Status))}</td>");
                sb.AppendLine($"<td>{entry.Events.Count}</td>");
                sb.AppendLine("</tr>");
            }
            sb.AppendLine("</table>");
        }

        if (!string.IsNullOrEmpty(options.Notes))
        {
            sb.AppendLine($"<h2>📝 {H(T("report.notes"))}</h2>");
            sb.AppendLine("<div class='info-box'>");
            sb.AppendLine(H(options.Notes).Replace("\n", "<br>"));
            sb.AppendLine("</div>");
        }

        sb.AppendLine("<div style='margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #7f8c8d;'>");
        sb.AppendLine($"<p>{H(F("report.footer", Timestamp(now)))}</p>");
        sb.AppendLine("</div>");
        sb.AppendLine("</div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return Task.FromResult(sb.ToString());
    }

    // ================================================================ JSON (campos estáveis, sem tradução)

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static Task<string> GenerateJSONReportAsync(ScanResult scanResult, Dictionary<string, DeviceHistoryEntry> history, AuditReportOptions options)
    {
        var report = new
        {
            Metadata = new
            {
                GeneratedAt = DateTime.Now,
                Language = Instance.Language,
                ScanDuration = scanResult.Duration.TotalSeconds,
                scanResult.ScanMethod,
                Auditor = options.AuditorName,
                options.Notes,
                scanResult.VulnerabilitySourceNote
            },
            scanResult.Network,
            Summary = new
            {
                TotalDevices = scanResult.Devices.Count,
                OnlineDevices = scanResult.Devices.Count(d => d.Status == "Online"),
                OfflineDevices = history.Count(h => h.Value.Status == "Offline"),
                TotalVulnerabilities = scanResult.Devices.Sum(d => d.Vulnerabilities.Count),
                CriticalVulnerabilities = scanResult.Devices.Sum(d => d.Vulnerabilities.Count(v => v.Severity == "Critical")),
                HighVulnerabilities = scanResult.Devices.Sum(d => d.Vulnerabilities.Count(v => v.Severity == "High"))
            },
            Devices = scanResult.Devices.Select(d => new
            {
                d.IpAddress,
                d.MacAddress,
                d.Hostname,
                d.FriendlyName,
                d.Vendor,
                d.Model,
                d.ModelId,
                d.OperatingSystem,
                d.OSConfidence,
                d.DeviceType,
                DeviceTypeLabel = Loc.DeviceType(d.DeviceType),
                d.Status,
                d.OpenPorts,
                Services = options.IncludeServices ? d.Services : null,
                Vulnerabilities = options.IncludeVulnerabilities ? d.Vulnerabilities : null,
                d.LastSeen
            }),
            History = options.IncludeHistory ? history.Values.Select(h => new
            {
                h.IpAddress,
                h.MacAddress,
                h.Hostname,
                h.FriendlyName,
                h.Vendor,
                h.DeviceType,
                h.Status,
                h.FirstSeenAt,
                h.SeenAt,
                h.LastLeftAt,
                EventCount = h.Events.Count
            }) : null
        };

        return Task.FromResult(JsonSerializer.Serialize(report, JsonOptions));
    }

    // ================================================================ Markdown

    public static Task<string> GenerateMarkdownReportAsync(ScanResult scanResult, Dictionary<string, DeviceHistoryEntry> history, AuditReportOptions options)
    {
        var sb = new StringBuilder();
        var now = DateTime.Now;

        sb.AppendLine($"# 🔒 {T("report.title")}");
        sb.AppendLine();
        sb.AppendLine($"**{T("report.date")}:** {Timestamp(now)}  ");
        sb.AppendLine($"**{T("report.duration")}:** {scanResult.Duration.TotalSeconds.ToString("F1", Instance.Culture)} s  ");
        sb.AppendLine($"**{T("report.method")}:** {scanResult.ScanMethod}  ");
        if (!string.IsNullOrEmpty(options.AuditorName))
            sb.AppendLine($"**{T("report.auditor")}:** {options.AuditorName}  ");
        sb.AppendLine();

        if (scanResult.Network is { } net)
        {
            sb.AppendLine($"## 📡 {T("report.network")}");
            sb.AppendLine();
            sb.AppendLine($"- **{T("report.localIp")}:** {net.IpAddress}");
            sb.AppendLine($"- **{T("report.mask")}:** {net.SubnetMask}");
            sb.AppendLine($"- **{T("net.network")}:** {net.NetworkRange}");
            sb.AppendLine($"- **Gateway:** {net.Gateway}");
            sb.AppendLine($"- **Hostname:** {net.Hostname}");
            sb.AppendLine($"- **{T("report.interface")}:** {net.InterfaceName}");
            sb.AppendLine();
        }

        var totalVulns = scanResult.Devices.Sum(d => d.Vulnerabilities.Count);
        sb.AppendLine($"## 📊 {T("report.summary")}");
        sb.AppendLine();
        sb.AppendLine($"- **{T("nav.devices")}:** {scanResult.Devices.Count}");
        sb.AppendLine($"- **{T("status.online")}:** {scanResult.Devices.Count(d => d.Status == "Online")}");
        sb.AppendLine($"- **{T("status.offline")}:** {history.Count(h => h.Value.Status == "Offline")}");
        sb.AppendLine($"- **{T("options.vulns")}:** {totalVulns}");
        sb.AppendLine();

        if (options.IncludeVulnerabilities && totalVulns > 0)
        {
            sb.AppendLine($"## ⚠️ {T("report.vulns")}");
            sb.AppendLine();
            sb.AppendLine($"> {T("report.disclaimer")}");
            if (!string.IsNullOrEmpty(scanResult.VulnerabilitySourceNote))
                sb.AppendLine($">\n> {scanResult.VulnerabilitySourceNote}");
            sb.AppendLine();

            foreach (var device in scanResult.Devices.Where(d => d.Vulnerabilities.Count > 0))
            {
                sb.AppendLine($"### {MdCell(device.DisplayName)} ({device.IpAddress})");
                sb.AppendLine();
                sb.AppendLine($"| CVE | {T("report.col.severity")} | CVSS | KEV | {T("report.col.service")} | {T("report.col.description")} |");
                sb.AppendLine("|-----|------|------|-----|------|------|");
                foreach (var vuln in device.Vulnerabilities)
                {
                    var service = F("vuln.where", vuln.Product, vuln.DetectedVersion, vuln.Port) + (vuln.MayBeBackported ? " ⚠ " + T("report.backport") : "");
                    sb.AppendLine($"| [{vuln.CVE}]({vuln.Url}) | {Severity(vuln.Severity)} | {CvssText(vuln)} | {Kev(vuln)} | {MdCell(service)} | {MdCell(vuln.Description)} |");
                }
                sb.AppendLine();
            }
        }

        sb.AppendLine($"## 🖥️ {T("report.devices")}");
        sb.AppendLine();
        foreach (var device in scanResult.Devices)
        {
            sb.AppendLine($"### {MdCell(device.DisplayName)} ({device.IpAddress})");
            sb.AppendLine($"- **MAC:** {device.MacAddress}");
            sb.AppendLine($"- **{T("details.vendor")}:** {ExportService.VendorText(device.Vendor)}");
            if (!string.IsNullOrWhiteSpace(device.Model))
                sb.AppendLine($"- **{T("details.model")}:** {device.Model}");
            if (options.IncludeOSInfo && !string.IsNullOrEmpty(device.OperatingSystem))
                sb.AppendLine($"- **{T("details.os")}:** {device.OperatingSystem} ({device.OSConfidence})");
            sb.AppendLine($"- **{T("csv.type")}:** {Loc.DeviceType(device.DeviceType)}");
            sb.AppendLine($"- **{T("csv.status")}:** {Status(device.Status)}");
            sb.AppendLine($"- **{T("csv.ports")}:** {Dash(device.OpenPorts)}");

            if (options.IncludeServices && device.Services.Count > 0)
            {
                sb.AppendLine($"- **{T("report.col.services")}:**");
                foreach (var s in device.Services)
                    sb.AppendLine($"  - {s.Port} · {s.Service} {s.Product} {s.Version}".TrimEnd());
            }

            if (options.IncludeVulnerabilities && device.Vulnerabilities.Count > 0)
            {
                sb.AppendLine($"- **{T("options.vulns")}:** {device.Vulnerabilities.Count}");
                foreach (var vuln in device.Vulnerabilities)
                {
                    var kev = vuln.IsKnownExploited ? " · " + T("security.exploited") : "";
                    sb.AppendLine($"  - [{Severity(vuln.Severity)} {CvssText(vuln)}] {vuln.CVE}{kev}");
                }
            }
            sb.AppendLine();
        }

        if (!string.IsNullOrEmpty(options.Notes))
        {
            sb.AppendLine($"## 📝 {T("report.notes")}");
            sb.AppendLine();
            sb.AppendLine(options.Notes);
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine($"*{F("report.footer", Timestamp(now))}*");

        return Task.FromResult(sb.ToString());
    }
}
