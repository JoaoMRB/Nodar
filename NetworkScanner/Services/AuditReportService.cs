using System.Text;
using NetworkScanner.Models;

namespace NetworkScanner.Services;

public static class AuditReportService
{
    /// <summary>
    /// Escapa texto para HTML. Banners, hostnames e descrições vêm da rede ou de fontes externas e
    /// nunca podem ser inseridos no relatório sem escape (injeção de HTML/JavaScript).
    /// </summary>
    private static string H(string? value) => System.Net.WebUtility.HtmlEncode(value ?? "");

    private const string VulnerabilityDisclaimer =
        "Correspondência pela versão anunciada no banner, com dados da NVD (NIST) e do catálogo CISA KEV. " +
        "Não confirma que o dispositivo está vulnerável: configuração, módulos ativos e correções aplicadas " +
        "pelo fabricante ou pela distribuição (backports) podem mudar o resultado.";

    /// <summary>Texto seguro para uma célula de tabela Markdown (sem quebras de linha nem barras verticais).</summary>
    private static string MdCell(string? value) =>
        (value ?? "").Replace("\r", " ").Replace("\n", " ").Replace("|", "\\|");

    private static string CvssText(VulnerabilityInfo v) =>
        v.CvssScore.HasValue ? $"{v.CvssScore:0.0} (v{v.CvssVersion})" : "—";

    public class AuditReportOptions
    {
        public bool IncludeVulnerabilities { get; set; } = true;
        public bool IncludeServices { get; set; } = true;
        public bool IncludeOSInfo { get; set; } = true;
        public bool IncludeHistory { get; set; } = true;
        public string AuditorName { get; set; } = "";
        public string Notes { get; set; } = "";
    }

    public static async Task<string> GenerateHTMLReportAsync(ScanResult scanResult, Dictionary<string, DeviceHistoryEntry> history, AuditReportOptions options)
    {
        var sb = new StringBuilder();
        var timestamp = DateTime.Now;

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang='pt'>");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset='UTF-8'>");
        sb.AppendLine("<title>Relatório de Auditoria de Rede</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }");
        sb.AppendLine(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }");
        sb.AppendLine("h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }");
        sb.AppendLine("h2 { color: #34495e; margin-top: 30px; }");
        sb.AppendLine(".header { display: flex; justify-content: space-between; margin-bottom: 30px; }");
        sb.AppendLine(".info-box { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }");
        sb.AppendLine("table { width: 100%; border-collapse: collapse; margin: 20px 0; }");
        sb.AppendLine("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }");
        sb.AppendLine("th { background: #3498db; color: white; }");
        sb.AppendLine("tr:hover { background: #f5f5f5; }");
        sb.AppendLine(".severity-critical { color: #e74c3c; font-weight: bold; }");
        sb.AppendLine(".severity-high { color: #e67e22; font-weight: bold; }");
        sb.AppendLine(".severity-medium { color: #f39c12; font-weight: bold; }");
        sb.AppendLine(".severity-low { color: #27ae60; font-weight: bold; }");
        sb.AppendLine(".status-online { color: #27ae60; font-weight: bold; }");
        sb.AppendLine(".status-offline { color: #e74c3c; font-weight: bold; }");
        sb.AppendLine(".summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }");
        sb.AppendLine(".summary-card { background: #3498db; color: white; padding: 20px; border-radius: 5px; text-align: center; }");
        sb.AppendLine(".summary-card h3 { margin: 0; font-size: 2em; }");
        sb.AppendLine(".summary-card p { margin: 5px 0 0 0; opacity: 0.9; }");
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("<div class='container'>");

        // Header
        sb.AppendLine("<h1>🔒 Relatório de Auditoria de Rede</h1>");
        sb.AppendLine("<div class='header'>");
        sb.AppendLine($"<div><strong>Data:</strong> {timestamp:dd/MM/yyyy HH:mm:ss}</div>");
        sb.AppendLine($"<div><strong>Duração do Scan:</strong> {scanResult.Duration.TotalSeconds:F1}s</div>");
        sb.AppendLine($"<div><strong>Método:</strong> {scanResult.ScanMethod}</div>");
        if (!string.IsNullOrEmpty(options.AuditorName))
        {
            sb.AppendLine($"<div><strong>Auditor:</strong> {H(options.AuditorName)}</div>");
        }
        sb.AppendLine("</div>");

        // Network Info
        if (scanResult.Network != null)
        {
            sb.AppendLine("<h2>📡 Informação da Rede</h2>");
            sb.AppendLine("<div class='info-box'>");
            sb.AppendLine($"<strong>IP Local:</strong> {scanResult.Network.IpAddress}<br>");
            sb.AppendLine($"<strong>Máscara:</strong> {scanResult.Network.SubnetMask}<br>");
            sb.AppendLine($"<strong>Rede:</strong> {scanResult.Network.NetworkRange}<br>");
            sb.AppendLine($"<strong>Gateway:</strong> {scanResult.Network.Gateway}<br>");
            sb.AppendLine($"<strong>Hostname:</strong> {H(scanResult.Network.Hostname)}<br>");
            sb.AppendLine($"<strong>Interface:</strong> {H(scanResult.Network.InterfaceName)}");
            sb.AppendLine("</div>");
        }

        // Summary Statistics
        var totalDevices = scanResult.Devices.Count;
        var onlineDevices = scanResult.Devices.Count(d => d.Status == "Online");
        var offlineDevices = history.Count(h => h.Value.Status == "Offline");
        var totalVulns = scanResult.Devices.Sum(d => d.Vulnerabilities.Count);
        var criticalVulns = scanResult.Devices.Sum(d => d.Vulnerabilities.Count(v => v.Severity == "Critical"));
        var highVulns = scanResult.Devices.Sum(d => d.Vulnerabilities.Count(v => v.Severity == "High"));

        sb.AppendLine("<h2>📊 Resumo</h2>");
        sb.AppendLine("<div class='summary'>");
        sb.AppendLine($"<div class='summary-card'><h3>{totalDevices}</h3><p>Dispositivos</p></div>");
        sb.AppendLine($"<div class='summary-card' style='background: #27ae60;'><h3>{onlineDevices}</h3><p>Online</p></div>");
        sb.AppendLine($"<div class='summary-card' style='background: #e74c3c;'><h3>{offlineDevices}</h3><p>Offline</p></div>");
        sb.AppendLine($"<div class='summary-card' style='background: #e67e22;'><h3>{totalVulns}</h3><p>Vulnerabilidades</p></div>");
        if (criticalVulns > 0)
        {
            sb.AppendLine($"<div class='summary-card' style='background: #c0392b;'><h3>{criticalVulns}</h3><p>Críticas</p></div>");
        }
        sb.AppendLine("</div>");

        // Vulnerability Summary
        if (options.IncludeVulnerabilities && totalVulns > 0)
        {
            sb.AppendLine("<h2>⚠️ Vulnerabilidades potenciais</h2>");
            sb.AppendLine($"<p><em>{H(VulnerabilityDisclaimer)}</em></p>");
            if (!string.IsNullOrEmpty(scanResult.VulnerabilitySourceNote))
                sb.AppendLine($"<p><em>{H(scanResult.VulnerabilitySourceNote)}</em></p>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>Dispositivo</th><th>Serviço</th><th>Severidade</th><th>CVSS</th><th>CVE</th><th>Explorada (KEV)</th><th>Descrição</th></tr>");

            foreach (var device in scanResult.Devices.Where(d => d.Vulnerabilities.Any()))
            {
                foreach (var vuln in device.Vulnerabilities)
                {
                    var severityClass = vuln.Severity.ToLower() switch
                    {
                        "critical" => "severity-critical",
                        "high" => "severity-high",
                        "medium" => "severity-medium",
                        _ => "severity-low"
                    };

                    var kev = vuln.IsKnownExploited
                        ? (vuln.KnownRansomwareUse ? "Sim (ransomware)" : "Sim")
                        : "—";
                    var backport = vuln.MayBeBackported ? " <small>(pacote de distribuição: confirmar)</small>" : "";

                    sb.AppendLine("<tr>");
                    sb.AppendLine($"<td>{H(device.DisplayName)} ({H(device.IpAddress)})</td>");
                    sb.AppendLine($"<td>{H(vuln.Product)} {H(vuln.DetectedVersion)} · porta {vuln.Port}{backport}</td>");
                    sb.AppendLine($"<td class='{severityClass}'>{H(vuln.Severity)}</td>");
                    sb.AppendLine($"<td>{H(CvssText(vuln))}</td>");
                    sb.AppendLine($"<td><a href='{H(vuln.Url)}'>{H(vuln.CVE)}</a></td>");
                    sb.AppendLine($"<td>{H(kev)}</td>");
                    sb.AppendLine($"<td>{H(vuln.Description)}</td>");
                    sb.AppendLine("</tr>");
                }
            }
            sb.AppendLine("</table>");
        }

        // Device Details
        sb.AppendLine("<h2>🖥️ Detalhes dos Dispositivos</h2>");
        sb.AppendLine("<table>");
        sb.AppendLine("<tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Fabricante</th><th>OS</th><th>Tipo</th><th>Estado</th>");
        
        if (options.IncludeServices)
        {
            sb.AppendLine("<th>Serviços</th>");
        }
        
        if (options.IncludeVulnerabilities)
        {
            sb.AppendLine("<th>Vulns</th>");
        }
        
        sb.AppendLine("</tr>");

        foreach (var device in scanResult.Devices)
        {
            var statusClass = device.Status == "Online" ? "status-online" : "status-offline";
            var osInfo = options.IncludeOSInfo ? 
                (string.IsNullOrEmpty(device.OperatingSystem) ? "—" : $"{device.OperatingSystem} ({device.OSConfidence})") : "—";

            sb.AppendLine("<tr>");
            sb.AppendLine($"<td>{H(device.IpAddress)}</td>");
            sb.AppendLine($"<td>{H(device.MacAddress)}</td>");
            sb.AppendLine($"<td>{H(string.IsNullOrEmpty(device.Hostname) ? "—" : device.Hostname)}</td>");
            sb.AppendLine($"<td>{H(device.Vendor)}</td>");
            sb.AppendLine($"<td>{H(osInfo)}</td>");
            sb.AppendLine($"<td>{H(device.DeviceType)}</td>");
            sb.AppendLine($"<td class='{statusClass}'>{device.Status}</td>");

            if (options.IncludeServices)
            {
                var servicesList = device.Services.Any() ? 
                    string.Join("<br>", device.Services.Select(s => H($"{s.Service} {s.Product} {s.Version}"))) : "—";
                sb.AppendLine($"<td>{servicesList}</td>");
            }

            if (options.IncludeVulnerabilities)
            {
                var vulnCount = device.Vulnerabilities.Count;
                var severityClass = vulnCount > 0 ? "high" : "low";
                var vulnText = vulnCount > 0 ? $"<span class='severity-{severityClass}'>{vulnCount}</span>" : "—";
                sb.AppendLine($"<td>{vulnText}</td>");
            }

            sb.AppendLine("</tr>");

            // Detailed service info
            if (options.IncludeServices && device.Services.Any())
            {
                sb.AppendLine("<tr><td colspan='10' style='background: #f9f9f9;'>");
                sb.AppendLine("<strong>Serviços Detalhados:</strong><br>");
                foreach (var service in device.Services)
                {
                    sb.AppendLine(H($"Porta {service.Port}: {service.Service} {service.Product} {service.Version}"));
                    if (!string.IsNullOrEmpty(service.Banner))
                    {
                        sb.AppendLine($"<em>Banner: {H(service.Banner.Substring(0, Math.Min(100, service.Banner.Length)))}...</em>");
                    }
                    sb.AppendLine("<br>");
                }
                sb.AppendLine("</td></tr>");
            }
        }
        sb.AppendLine("</table>");

        // Historical Data
        if (options.IncludeHistory && history.Any())
        {
            sb.AppendLine("<h2>📜 Histórico de Dispositivos</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>IP</th><th>Hostname</th><th>Último Visto</th><th>Estado</th><th>Eventos</th></tr>");

            foreach (var entry in history.Values.OrderByDescending(h => h.SeenAt))
            {
                var lastSeen = entry.Status == "Offline" && entry.LastLeftAt.HasValue ?
                    $"{entry.LastLeftAt:dd/MM/yyyy HH:mm}" :
                    $"{entry.SeenAt:dd/MM/yyyy HH:mm}";

                sb.AppendLine("<tr>");
                sb.AppendLine($"<td>{entry.IpAddress}</td>");
                sb.AppendLine($"<td>{H(string.IsNullOrEmpty(entry.Hostname) ? "—" : entry.Hostname)}</td>");
                sb.AppendLine($"<td>{lastSeen}</td>");
                sb.AppendLine($"<td class='{(entry.Status == "Online" ? "status-online" : "status-offline")}'>{entry.Status}</td>");
                sb.AppendLine($"<td>{entry.Events.Count} eventos</td>");
                sb.AppendLine("</tr>");
            }
            sb.AppendLine("</table>");
        }

        // Notes
        if (!string.IsNullOrEmpty(options.Notes))
        {
            sb.AppendLine("<h2>📝 Notas</h2>");
            sb.AppendLine("<div class='info-box'>");
            sb.AppendLine(H(options.Notes).Replace("\n", "<br>"));
            sb.AppendLine("</div>");
        }

        // Footer
        sb.AppendLine("<div style='margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #7f8c8d;'>");
        sb.AppendLine("<p>Relatório gerado por Nodar - Ferramenta de Auditoria de Rede</p>");
        sb.AppendLine($"<p>Gerado em {timestamp:dd/MM/yyyy HH:mm:ss}</p>");
        sb.AppendLine("</div>");

        sb.AppendLine("</div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    public static async Task<string> GenerateJSONReportAsync(ScanResult scanResult, Dictionary<string, DeviceHistoryEntry> history, AuditReportOptions options)
    {
        var report = new
        {
            Metadata = new
            {
                GeneratedAt = DateTime.Now,
                ScanDuration = scanResult.Duration.TotalSeconds,
                ScanMethod = scanResult.ScanMethod,
                Auditor = options.AuditorName,
                Notes = options.Notes
            },
            Network = scanResult.Network,
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
                d.Vendor,
                d.OperatingSystem,
                d.OSConfidence,
                d.DeviceType,
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
                h.Vendor,
                h.DeviceType,
                h.Status,
                h.SeenAt,
                h.LastLeftAt,
                EventCount = h.Events.Count
            }) : null
        };

        return System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions 
        { 
            WriteIndented = true 
        });
    }

    public static async Task<string> GenerateMarkdownReportAsync(ScanResult scanResult, Dictionary<string, DeviceHistoryEntry> history, AuditReportOptions options)
    {
        var sb = new StringBuilder();
        var timestamp = DateTime.Now;

        sb.AppendLine("# 🔒 Relatório de Auditoria de Rede");
        sb.AppendLine();
        sb.AppendLine($"**Data:** {timestamp:dd/MM/yyyy HH:mm:ss}  ");
        sb.AppendLine($"**Duração do Scan:** {scanResult.Duration.TotalSeconds:F1}s  ");
        sb.AppendLine($"**Método:** {scanResult.ScanMethod}  ");
        
        if (!string.IsNullOrEmpty(options.AuditorName))
        {
            sb.AppendLine($"**Auditor:** {options.AuditorName}  ");
        }
        
        sb.AppendLine();

        // Network Info
        if (scanResult.Network != null)
        {
            sb.AppendLine("## 📡 Informação da Rede");
            sb.AppendLine();
            sb.AppendLine($"- **IP Local:** {scanResult.Network.IpAddress}");
            sb.AppendLine($"- **Máscara:** {scanResult.Network.SubnetMask}");
            sb.AppendLine($"- **Rede:** {scanResult.Network.NetworkRange}");
            sb.AppendLine($"- **Gateway:** {scanResult.Network.Gateway}");
            sb.AppendLine($"- **Hostname:** {scanResult.Network.Hostname}");
            sb.AppendLine($"- **Interface:** {scanResult.Network.InterfaceName}");
            sb.AppendLine();
        }

        // Summary
        var totalVulns = scanResult.Devices.Sum(d => d.Vulnerabilities.Count);
        sb.AppendLine("## 📊 Resumo");
        sb.AppendLine();
        sb.AppendLine($"- **Total Dispositivos:** {scanResult.Devices.Count}");
        sb.AppendLine($"- **Online:** {scanResult.Devices.Count(d => d.Status == "Online")}");
        sb.AppendLine($"- **Offline:** {history.Count(h => h.Value.Status == "Offline")}");
        sb.AppendLine($"- **Vulnerabilidades:** {totalVulns}");
        sb.AppendLine();

        // Vulnerabilities
        if (options.IncludeVulnerabilities && totalVulns > 0)
        {
            sb.AppendLine("## ⚠️ Vulnerabilidades potenciais");
            sb.AppendLine();
            sb.AppendLine($"> {VulnerabilityDisclaimer}");
            if (!string.IsNullOrEmpty(scanResult.VulnerabilitySourceNote))
                sb.AppendLine($">\n> {scanResult.VulnerabilitySourceNote}");
            sb.AppendLine();

            foreach (var device in scanResult.Devices.Where(d => d.Vulnerabilities.Count > 0))
            {
                sb.AppendLine($"### {device.DisplayName} ({device.IpAddress})");
                sb.AppendLine();
                sb.AppendLine("| CVE | Severidade | CVSS | KEV | Serviço | Descrição |");
                sb.AppendLine("|-----|------------|------|-----|---------|-----------|");
                foreach (var vuln in device.Vulnerabilities)
                {
                    var kev = vuln.IsKnownExploited ? (vuln.KnownRansomwareUse ? "Sim (ransomware)" : "Sim") : "—";
                    var service = $"{vuln.Product} {vuln.DetectedVersion} :{vuln.Port}" + (vuln.MayBeBackported ? " ⚠ distro" : "");
                    sb.AppendLine($"| [{vuln.CVE}]({vuln.Url}) | {vuln.Severity} | {CvssText(vuln)} | {kev} | {MdCell(service)} | {MdCell(vuln.Description)} |");
                }
                sb.AppendLine();
            }
        }

        // Devices
        sb.AppendLine("## 🖥️ Dispositivos");
        sb.AppendLine();
        
        foreach (var device in scanResult.Devices)
        {
            sb.AppendLine($"### {device.DisplayName} ({device.IpAddress})");
            sb.AppendLine($"- **MAC:** {device.MacAddress}");
            sb.AppendLine($"- **Fabricante:** {device.Vendor}");
            
            if (options.IncludeOSInfo && !string.IsNullOrEmpty(device.OperatingSystem))
            {
                sb.AppendLine($"- **OS:** {device.OperatingSystem} ({device.OSConfidence})");
            }
            
            sb.AppendLine($"- **Tipo:** {device.DeviceType}");
            sb.AppendLine($"- **Estado:** {device.Status}");
            sb.AppendLine($"- **Portas:** {device.OpenPorts ?? "Nenhuma"}");

            if (options.IncludeServices && device.Services.Any())
            {
                sb.AppendLine($"- **Serviços:**");
                foreach (var service in device.Services)
                {
                    sb.AppendLine($"  - Porta {service.Port}: {service.Service} {service.Product} {service.Version}");
                }
            }

            if (options.IncludeVulnerabilities && device.Vulnerabilities.Any())
            {
                sb.AppendLine($"- **Vulnerabilidades:** {device.Vulnerabilities.Count}");
                foreach (var vuln in device.Vulnerabilities)
                {
                    var kev = vuln.IsKnownExploited ? " · explorada (KEV)" : "";
                    sb.AppendLine($"  - [{vuln.Severity} {CvssText(vuln)}] {vuln.CVE}{kev}");
                }
            }

            sb.AppendLine();
        }

        // Notes
        if (!string.IsNullOrEmpty(options.Notes))
        {
            sb.AppendLine("## 📝 Notas");
            sb.AppendLine();
            sb.AppendLine(options.Notes);
            sb.AppendLine();
        }

        sb.AppendLine("---");
        sb.AppendLine("*Relatório gerado por Nodar*");

        return sb.ToString();
    }
}
