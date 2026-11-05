using System.Text.RegularExpressions;

namespace Nodar.Core.Services;

public static class OSFingerprintDatabase
{
    public class OSFingerprint
    {
        public string OSName { get; set; } = "";
        public string OSVersion { get; set; } = "";
        public string OSFamily { get; set; } = "";
        public int? TTL { get; set; }
        public int? WindowSize { get; set; }
        public string? MSS { get; set; }
        public bool? DF { get; set; }
        public string? Flags { get; set; }
        public int? PortBehavior { get; set; }
        public double Confidence { get; set; }
    }

    private static readonly List<OSFingerprint> Fingerprints = new()
    {
        // Windows Fingerprints
        new OSFingerprint
        {
            OSName = "Windows",
            OSVersion = "10/11",
            OSFamily = "Windows",
            TTL = 128,
            WindowSize = 8192,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 1,
            Confidence = 0.95
        },
        new OSFingerprint
        {
            OSName = "Windows",
            OSVersion = "8.1/10",
            OSFamily = "Windows",
            TTL = 128,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 1,
            Confidence = 0.90
        },
        new OSFingerprint
        {
            OSName = "Windows",
            OSVersion = "7/Server 2008 R2",
            OSFamily = "Windows",
            TTL = 128,
            WindowSize = 8192,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 1,
            Confidence = 0.85
        },
        new OSFingerprint
        {
            OSName = "Windows",
            OSVersion = "XP/Server 2003",
            OSFamily = "Windows",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = false,
            Flags = "S",
            PortBehavior = 1,
            Confidence = 0.80
        },
        new OSFingerprint
        {
            OSName = "Windows",
            OSVersion = "Server 2012/2016/2019",
            OSFamily = "Windows",
            TTL = 128,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 1,
            Confidence = 0.92
        },

        // Linux Fingerprints
        new OSFingerprint
        {
            OSName = "Linux",
            OSVersion = "5.x (Kernel 5.x)",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.90
        },
        new OSFingerprint
        {
            OSName = "Linux",
            OSVersion = "4.x (Kernel 4.x)",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 29200,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.88
        },
        new OSFingerprint
        {
            OSName = "Linux",
            OSVersion = "3.x (Kernel 3.x)",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.85
        },
        new OSFingerprint
        {
            OSName = "Ubuntu",
            OSVersion = "20.04/22.04 LTS",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 64240,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.92
        },
        new OSFingerprint
        {
            OSName = "Debian",
            OSVersion = "10/11/12",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.90
        },
        new OSFingerprint
        {
            OSName = "CentOS/RHEL",
            OSVersion = "7/8/9",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.88
        },
        new OSFingerprint
        {
            OSName = "Fedora",
            OSVersion = "35/36/37",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 64240,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.87
        },

        // macOS Fingerprints
        new OSFingerprint
        {
            OSName = "macOS",
            OSVersion = "Ventura (13.x)",
            OSFamily = "macOS",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 3,
            Confidence = 0.93
        },
        new OSFingerprint
        {
            OSName = "macOS",
            OSVersion = "Monterey (12.x)",
            OSFamily = "macOS",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 3,
            Confidence = 0.91
        },
        new OSFingerprint
        {
            OSName = "macOS",
            OSVersion = "Big Sur (11.x)",
            OSFamily = "macOS",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 3,
            Confidence = 0.89
        },
        new OSFingerprint
        {
            OSName = "macOS",
            OSVersion = "Catalina (10.15.x)",
            OSFamily = "macOS",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 3,
            Confidence = 0.85
        },

        // Network Devices
        new OSFingerprint
        {
            OSName = "Cisco IOS",
            OSVersion = "12.x/15.x",
            OSFamily = "Network",
            TTL = 255,
            WindowSize = 4128,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.88
        },
        new OSFingerprint
        {
            OSName = "Cisco IOS-XE",
            OSVersion = "16.x/17.x",
            OSFamily = "Network",
            TTL = 255,
            WindowSize = 4128,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.90
        },
        new OSFingerprint
        {
            OSName = "Juniper JunOS",
            OSVersion = "20.x/21.x",
            OSFamily = "Network",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.87
        },
        new OSFingerprint
        {
            OSName = "Ubiquiti EdgeOS",
            OSVersion = "1.x/2.x",
            OSFamily = "Network",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.85
        },
        new OSFingerprint
        {
            OSName = "MikroTik RouterOS",
            OSVersion = "6.x/7.x",
            OSFamily = "Network",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.86
        },

        // BSD Systems
        new OSFingerprint
        {
            OSName = "FreeBSD",
            OSVersion = "12.x/13.x",
            OSFamily = "BSD",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 5,
            Confidence = 0.88
        },
        new OSFingerprint
        {
            OSName = "OpenBSD",
            OSVersion = "6.x/7.x",
            OSFamily = "BSD",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 5,
            Confidence = 0.90
        },
        new OSFingerprint
        {
            OSName = "NetBSD",
            OSVersion = "9.x/10.x",
            OSFamily = "BSD",
            TTL = 64,
            WindowSize = 16384,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 5,
            Confidence = 0.85
        },

        // Mobile Devices
        new OSFingerprint
        {
            OSName = "Android",
            OSVersion = "12/13/14",
            OSFamily = "Mobile",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 6,
            Confidence = 0.87
        },
        new OSFingerprint
        {
            OSName = "iOS",
            OSVersion = "15/16/17",
            OSFamily = "Mobile",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 6,
            Confidence = 0.91
        },

        // Embedded/IoT
        new OSFingerprint
        {
            OSName = "Embedded Linux",
            OSVersion = "BusyBox/OpenWrt",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.75
        },
        new OSFingerprint
        {
            OSName = "IoT Device",
            OSVersion = "Unknown",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 1460,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.60
        },

        // Virtualization
        new OSFingerprint
        {
            OSName = "VMware ESXi",
            OSVersion = "7.x/8.x",
            OSFamily = "Virtualization",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 8,
            Confidence = 0.90
        },
        new OSFingerprint
        {
            OSName = "Proxmox VE",
            OSVersion = "7.x/8.x",
            OSFamily = "Virtualization",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 8,
            Confidence = 0.88
        },

        // Additional Windows variants
        new OSFingerprint
        {
            OSName = "Windows",
            OSVersion = "Server 2022",
            OSFamily = "Windows",
            TTL = 128,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 1,
            Confidence = 0.94
        },
        new OSFingerprint
        {
            OSName = "Windows",
            OSVersion = "11",
            OSFamily = "Windows",
            TTL = 128,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 1,
            Confidence = 0.93
        },

        // Additional Linux distros
        new OSFingerprint
        {
            OSName = "Arch Linux",
            OSVersion = "Rolling",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 64240,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.86
        },
        new OSFingerprint
        {
            OSName = "Gentoo Linux",
            OSVersion = "Rolling",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.84
        },
        new OSFingerprint
        {
            OSName = "Alpine Linux",
            OSVersion = "3.x",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.82
        },

        // Network appliances
        new OSFingerprint
        {
            OSName = "Palo Alto PAN-OS",
            OSVersion = "10.x/11.x",
            OSFamily = "Network",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.89
        },
        new OSFingerprint
        {
            OSName = "Fortinet FortiOS",
            OSVersion = "6.x/7.x",
            OSFamily = "Network",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.88
        },
        new OSFingerprint
        {
            OSName = "SonicWall",
            OSVersion = "7.x",
            OSFamily = "Network",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 4,
            Confidence = 0.85
        },

        // Storage systems
        new OSFingerprint
        {
            OSName = "Synology DSM",
            OSVersion = "6.x/7.x",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.90
        },
        new OSFingerprint
        {
            OSName = "QNAP QTS",
            OSVersion = "4.x/5.x",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.88
        },

        // Printers/Scanners
        new OSFingerprint
        {
            OSName = "HP Printer",
            OSVersion = "Embedded",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.70
        },
        new OSFingerprint
        {
            OSName = "Canon Printer",
            OSVersion = "Embedded",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.68
        },

        // Cameras
        new OSFingerprint
        {
            OSName = "IP Camera",
            OSVersion = "Embedded Linux",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.72
        },

        // Gaming consoles
        new OSFingerprint
        {
            OSName = "PlayStation",
            OSVersion = "4/5",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 6,
            Confidence = 0.85
        },
        new OSFingerprint
        {
            OSName = "Xbox",
            OSVersion = "One/Series X",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 6,
            Confidence = 0.84
        },

        // Smart Home
        new OSFingerprint
        {
            OSName = "Amazon Echo",
            OSVersion = "Fire OS",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.78
        },
        new OSFingerprint
        {
            OSName = "Google Home",
            OSVersion = "Cast OS",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.76
        },
        new OSFingerprint
        {
            OSName = "Philips Hue",
            OSVersion = "Zigbee Bridge",
            OSFamily = "Embedded",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 7,
            Confidence = 0.74
        },

        // Docker containers
        new OSFingerprint
        {
            OSName = "Docker Container",
            OSVersion = "Linux",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 5840,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.80
        },

        // Kubernetes
        new OSFingerprint
        {
            OSName = "Kubernetes Node",
            OSVersion = "Linux",
            OSFamily = "Linux",
            TTL = 64,
            WindowSize = 65535,
            MSS = "1460",
            DF = true,
            Flags = "S",
            PortBehavior = 2,
            Confidence = 0.85
        }
    };

    public static List<OSFingerprint> MatchFingerprint(int ttl, int windowSize, string? mss, bool df, string flags, int portBehavior)
    {
        var matches = new List<OSFingerprint>();

        foreach (var fp in Fingerprints)
        {
            double score = 0;
            int factors = 0;

            // TTL matching (with tolerance)
            if (fp.TTL.HasValue)
            {
                factors++;
                if (Math.Abs(ttl - fp.TTL.Value) <= 32)
                    score += 0.3;
                else if (Math.Abs(ttl - fp.TTL.Value) <= 64)
                    score += 0.15;
            }

            // Window size matching
            if (fp.WindowSize.HasValue)
            {
                factors++;
                if (windowSize == fp.WindowSize.Value)
                    score += 0.25;
                else if (Math.Abs(windowSize - fp.WindowSize.Value) <= 1000)
                    score += 0.1;
            }

            // MSS matching
            if (!string.IsNullOrEmpty(fp.MSS) && !string.IsNullOrEmpty(mss))
            {
                factors++;
                if (mss == fp.MSS)
                    score += 0.15;
            }

            // DF flag matching
            if (fp.DF.HasValue)
            {
                factors++;
                if (df == fp.DF.Value)
                    score += 0.15;
            }

            // Flags matching
            if (!string.IsNullOrEmpty(fp.Flags) && !string.IsNullOrEmpty(flags))
            {
                factors++;
                if (flags.Contains(fp.Flags))
                    score += 0.1;
            }

            // Port behavior matching
            if (fp.PortBehavior.HasValue)
            {
                factors++;
                if (portBehavior == fp.PortBehavior.Value)
                    score += 0.05;
            }

            // Normalize score
            if (factors > 0)
            {
                score = score / factors;
                
                // Apply base confidence
                score *= fp.Confidence;

                if (score >= 0.5)
                {
                    var match = new OSFingerprint
                    {
                        OSName = fp.OSName,
                        OSVersion = fp.OSVersion,
                        OSFamily = fp.OSFamily,
                        Confidence = score
                    };
                    matches.Add(match);
                }
            }
        }

        return matches.OrderByDescending(m => m.Confidence).ToList();
    }

    public static OSFingerprint? GetBestMatch(int ttl, int windowSize, string? mss, bool df, string flags, int portBehavior)
    {
        var matches = MatchFingerprint(ttl, windowSize, mss, df, flags, portBehavior);
        return matches.FirstOrDefault();
    }
}
