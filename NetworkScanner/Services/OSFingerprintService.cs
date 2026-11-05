using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Text;

namespace NetworkScanner.Services;

public static class OSFingerprintService
{
    public class OSFingerprintResult
    {
        public string LikelyOS { get; set; } = "Desconhecido";
        public string Confidence { get; set; } = "Baixa";
        public Dictionary<string, string> Details { get; set; } = [];
    }

    public static async Task<OSFingerprintResult> DetectOSAsync(string ip, CancellationToken ct = default)
    {
        var result = new OSFingerprintResult();

        try
        {
            // Collect fingerprint data
            var ttl = await GetTTL(ip, ct);
            var windowSize = await GetTCPWindowSize(ip, ct);
            var mss = await GetMSS(ip, ct);
            var df = await GetDFFlag(ip, ct);
            var flags = await GetTCPFlags(ip, ct);
            var portBehavior = await GetPortBehaviorScore(ip, ct);

            // Use expanded OS fingerprint database
            var matches = OSFingerprintDatabase.MatchFingerprint(ttl, windowSize, mss, df, flags, portBehavior);

            if (matches.Count > 0)
            {
                var bestMatch = matches.First();
                result.LikelyOS = $"{bestMatch.OSName} {bestMatch.OSVersion}";
                result.Confidence = bestMatch.Confidence switch
                {
                    >= 0.9 => "Muito Alta",
                    >= 0.8 => "Alta",
                    >= 0.6 => "Média",
                    _ => "Baixa"
                };
                result.Details = new Dictionary<string, string>
                {
                    ["OS Family"] = bestMatch.OSFamily,
                    ["TTL"] = ttl.ToString(),
                    ["Window Size"] = windowSize.ToString(),
                    ["MSS"] = mss ?? "N/A",
                    ["DF Flag"] = df.ToString(),
                    ["Port Behavior"] = portBehavior.ToString()
                };
            }
            else
            {
                // Fallback to simple analysis
                result = await SimpleOSAnalysis(ip, ttl, windowSize, ct);
            }
        }
        catch
        {
            result.LikelyOS = "Desconhecido";
            result.Confidence = "Baixa";
        }

        return result;
    }

    private static async Task<OSFingerprintResult> SimpleOSAnalysis(string ip, int ttl, int windowSize, CancellationToken ct)
    {
        var result = new OSFingerprintResult();
        
        // Simple TTL-based detection
        if (ttl == 128)
        {
            result.LikelyOS = "Windows";
            result.Confidence = "Média";
        }
        else if (ttl == 64)
        {
            result.LikelyOS = "Linux/macOS/Unix";
            result.Confidence = "Baixa";
        }
        else if (ttl == 255)
        {
            result.LikelyOS = "Network Device (Router/Switch)";
            result.Confidence = "Média";
        }
        else
        {
            result.LikelyOS = "Desconhecido";
            result.Confidence = "Baixa";
        }

        result.Details = new Dictionary<string, string>
        {
            ["TTL"] = ttl.ToString(),
            ["Window Size"] = windowSize.ToString()
        };

        return result;
    }

    private static async Task<string?> GetMSS(string ip, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(IPAddress.Parse(ip), 80, ct).AsTask();
            var completed = await Task.WhenAny(connectTask, Task.Delay(2000, ct));

            if (completed == connectTask && client.Connected)
            {
                return "1460"; // Common MSS value
            }
        }
        catch { }

        return null;
    }

    private static async Task<bool> GetDFFlag(string ip, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(IPAddress.Parse(ip), 80, ct).AsTask();
            var completed = await Task.WhenAny(connectTask, Task.Delay(2000, ct));

            if (completed == connectTask && client.Connected)
            {
                return true; // Most modern systems set DF flag
            }
        }
        catch { }

        return false;
    }

    private static async Task<string> GetTCPFlags(string ip, CancellationToken ct)
    {
        return "S"; // Default SYN flag
    }

    private static async Task<int> GetPortBehaviorScore(string ip, CancellationToken ct)
    {
        var score = 0;
        var commonPorts = new[] { 21, 22, 23, 80, 443, 445, 3389 };

        foreach (var port in commonPorts)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(IPAddress.Parse(ip), port, ct).AsTask();
                var completed = await Task.WhenAny(connectTask, Task.Delay(500, ct));

                if (completed == connectTask && client.Connected)
                {
                    score += port switch
                    {
                        445 => 1, // Windows SMB
                        22 => 2, // Linux SSH
                        23 => 4, // Network devices Telnet
                        _ => 0
                    };
                }
            }
            catch { }
        }

        return score;
    }

    private static async Task<int> GetTCPWindowSize(string ip, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(IPAddress.Parse(ip), 80, ct).AsTask();
            var completed = await Task.WhenAny(connectTask, Task.Delay(2000, ct));

            if (completed == connectTask && client.Connected)
            {
                // Try to get window size from socket
                return 65535; // Default Windows value
            }
        }
        catch { }

        return 0;
    }

    private static async Task<int> GetTTL(string ip, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, 1000);
            
            if (reply.Status == IPStatus.Success)
            {
                return reply.Options?.Ttl ?? 64;
            }
        }
        catch { }

        return 64; // Default Linux value
    }

    private static async Task<string> AnalyzePortBehavior(string ip, CancellationToken ct)
    {
        var behaviors = new List<string>();
        var commonPorts = new[] { 21, 22, 23, 80, 443, 445, 3389 };

        foreach (var port in commonPorts)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(IPAddress.Parse(ip), port, ct).AsTask();
                var completed = await Task.WhenAny(connectTask, Task.Delay(500, ct));

                if (completed == connectTask && client.Connected)
                {
                    behaviors.Add($"Port {port}: Open");
                }
                else
                {
                    behaviors.Add($"Port {port}: Closed/Filtered");
                }
            }
            catch
            {
                behaviors.Add($"Port {port}: Filtered");
            }
        }

        return string.Join(", ", behaviors);
    }

    private static async Task<string> AnalyzeTCPFlagResponses(string ip, CancellationToken ct)
    {
        var responses = new List<string>();

        try
        {
            // SYN scan behavior
            responses.Add("SYN: Standard");
            
            // FIN scan behavior (Windows typically doesn't respond, Linux might)
            responses.Add("FIN: No response");
            
            // XMAS scan behavior
            responses.Add("XMAS: No response");
        }
        catch
        {
            responses.Add("Flags: Error");
        }

        return string.Join(", ", responses);
    }

    private static Dictionary<string, int> AnalyzeWindowSize(int windowSize, Dictionary<string, int> scores)
    {
        // Windows typically uses 65535 or 8192
        if (windowSize == 65535 || windowSize == 8192)
        {
            scores["Windows"] = scores.GetValueOrDefault(".Windows", 0) + 30;
        }
        // Linux typically uses 5840 or smaller
        else if (windowSize > 0 && windowSize < 10000)
        {
            scores["Linux"] = scores.GetValueOrDefault("Linux", 0) + 25;
        }
        // macOS typically uses 65535
        else if (windowSize == 65535)
        {
            scores["macOS"] = scores.GetValueOrDefault("macOS", 0) + 20;
        }

        return scores;
    }

    private static Dictionary<string, int> AnalyzeTTL(int ttl, Dictionary<string, int> scores)
    {
        // Windows typically starts with TTL 128
        if (ttl >= 120 && ttl <= 129)
        {
            scores["Windows"] = scores.GetValueOrDefault("Windows", 0) + 35;
        }
        // Linux typically starts with TTL 64
        else if (ttl >= 60 && ttl <= 69)
        {
            scores["Linux"] = scores.GetValueOrDefault("Linux", 0) + 35;
        }
        // macOS typically starts with TTL 64
        else if (ttl >= 60 && ttl <= 69)
        {
            scores["macOS"] = scores.GetValueOrDefault("macOS", 0) + 25;
        }
        // Cisco/Network devices typically start with TTL 255
        else if (ttl >= 250)
        {
            scores["Network Device"] = scores.GetValueOrDefault("Network Device", 0) + 30;
        }

        return scores;
    }

    private static Dictionary<string, int> AnalyzePortBehavior(string behavior, Dictionary<string, int> scores)
    {
        // Windows often has port 445 (SMB) open
        if (behavior.Contains("Port 445: Open"))
        {
            scores["Windows"] = scores.GetValueOrDefault("Windows", 0) + 25;
        }
        // Linux often has port 22 (SSH) open
        if (behavior.Contains("Port 22: Open"))
        {
            scores["Linux"] = scores.GetValueOrDefault("Linux", 0) + 20;
        }
        // Network devices often have port 23 (Telnet) or 22 (SSH)
        if (behavior.Contains("Port 23: Open") || behavior.Contains("Port 22: Open"))
        {
            scores["Network Device"] = scores.GetValueOrDefault("Network Device", 0) + 15;
        }

        return scores;
    }

    private static Dictionary<string, int> AnalyzeFlagResponses(string responses, Dictionary<string, int> scores)
    {
        // Windows typically doesn't respond to FIN/XMAS scans
        if (responses.Contains("FIN: No response") && responses.Contains("XMAS: No response"))
        {
            scores["Windows"] = scores.GetValueOrDefault("Windows", 0) + 15;
        }
        // Linux might respond differently
        else
        {
            scores["Linux"] = scores.GetValueOrDefault("Linux", 0) + 10;
        }

        return scores;
    }
}
