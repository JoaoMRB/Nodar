using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace Nodar.Core.Services;

public static class TracerouteService
{
    public class TracerouteHop
    {
        public int HopNumber { get; set; }
        public string IPAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public int RoundTripTime { get; set; }
        public bool TimedOut { get; set; }
    }

    public static async Task<List<TracerouteHop>> TraceRouteAsync(string target, int maxHops = 30, CancellationToken ct = default)
    {
        var hops = new List<TracerouteHop>();

        for (int ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();

            var hop = await TraceHopAsync(target, ttl, ct);
            hops.Add(hop);

            // Stop if we reached the target
            if (!hop.TimedOut && hop.IPAddress != "0.0.0.0")
            {
                try
                {
                    var targetIp = IPAddress.Parse(target);
                    if (IPAddress.Parse(hop.IPAddress).Equals(targetIp))
                        break;
                }
                catch { }
            }

            // Stop if we had 3 consecutive timeouts
            if (hops.Count >= 3 && 
                hops[^1].TimedOut && 
                hops[^2].TimedOut && 
                hops[^3].TimedOut)
            {
                break;
            }
        }

        return hops;
    }

    private static async Task<TracerouteHop> TraceHopAsync(string target, int ttl, CancellationToken ct)
    {
        var hop = new TracerouteHop
        {
            HopNumber = ttl,
            TimedOut = true
        };

        try
        {
            using var ping = new Ping();
            var options = new PingOptions(ttl, true);
            
            var reply = await ping.SendPingAsync(IPAddress.Parse(target), TimeSpan.FromMilliseconds(2000), new byte[32], options, ct);
            
            if (reply.Status == IPStatus.Success || reply.Status == IPStatus.TtlExpired)
            {
                hop.IPAddress = reply.Address.ToString();
                hop.RoundTripTime = (int)reply.RoundtripTime;
                hop.TimedOut = false;

                // Try to resolve hostname
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(reply.Address);
                    hop.Hostname = hostEntry.HostName;
                }
                catch
                {
                    hop.Hostname = "";
                }
            }
        }
        catch
        {
            hop.TimedOut = true;
        }

        return hop;
    }

    public static string GenerateTracerouteReport(List<TracerouteHop> hops)
    {
        var sb = new StringBuilder();
        sb.AppendLine("TRACEROUTE REPORT");
        sb.AppendLine("==================");
        sb.AppendLine();

        foreach (var hop in hops)
        {
            if (hop.TimedOut)
            {
                sb.AppendLine($"Hop {hop.HopNumber}: * * * Request timed out");
            }
            else
            {
                var hostname = string.IsNullOrEmpty(hop.Hostname) ? "" : $" ({hop.Hostname})";
                sb.AppendLine($"Hop {hop.HopNumber}: {hop.IPAddress}{hostname} - {hop.RoundTripTime}ms");
            }
        }

        return sb.ToString();
    }

    public static string AnalyzeRoute(List<TracerouteHop> hops)
    {
        var analysis = new StringBuilder();
        analysis.AppendLine("ROUTE ANALYSIS");
        analysis.AppendLine("==============");
        analysis.AppendLine();

        // Count hops
        analysis.AppendLine($"Total Hops: {hops.Count(h => !h.TimedOut)}");
        
        // Identify potential issues
        var timeoutHops = hops.Count(h => h.TimedOut);
        if (timeoutHops > 0)
        {
            analysis.AppendLine($"Timeouts: {timeoutHops} hops timed out");
        }

        // Check for high latency
        var highLatencyHops = hops.Where(h => !h.TimedOut && h.RoundTripTime > 200).ToList();
        if (highLatencyHops.Any())
        {
            analysis.AppendLine($"High Latency: {highLatencyHops.Count} hops with >200ms latency");
            foreach (var hop in highLatencyHops)
            {
                analysis.AppendLine($"  - Hop {hop.HopNumber}: {hop.RoundTripTime}ms");
            }
        }

        // Identify network segments
        analysis.AppendLine();
        analysis.AppendLine("Network Segments:");
        var segments = new List<string>();
        var lastSegment = "";
        
        foreach (var hop in hops.Where(h => !h.TimedOut))
        {
            var ipParts = hop.IPAddress.Split('.');
            if (ipParts.Length >= 3)
            {
                var segment = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.0/24";
                if (segment != lastSegment)
                {
                    segments.Add(segment);
                    lastSegment = segment;
                }
            }
        }

        foreach (var segment in segments.Distinct())
        {
            analysis.AppendLine($"  - {segment}");
        }

        return analysis.ToString();
    }
}
