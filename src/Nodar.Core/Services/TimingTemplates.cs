namespace Nodar.Core.Services;

public static class TimingTemplates
{
    public enum TimingLevel
    {
        Paranoid,    // T0 - Very slow, stealthy
        Sneaky,      // T1 - Slow, harder to detect
        Polite,      // T2 - Polite, respects network load
        Normal,      // T3 - Default, balanced
        Aggressive,  // T4 - Fast, good for modern networks
        Insane       // T5 - Very fast, may overwhelm network
    }

    public class TimingProfile
    {
        public int ScanDelay { get; set; } = 100;          // Delay between probes (ms)
        public int MaxParallelism { get; set; } = 1;        // Max parallel probes
        public int InitialRttTimeout { get; set; } = 1000;  // Initial RTT timeout (ms)
        public int MinRttTimeout { get; set; } = 100;       // Min RTT timeout (ms)
        public int MaxRttTimeout { get; set; } = 10000;     // Max RTT timeout (ms)
        public int HostTimeout { get; set; } = 900000;     // Total host timeout (ms)
        public int ScanTimeout { get; set; } = 300000;      // Total scan timeout (ms)
        public bool EnableStealth { get; set; } = false;    // Use stealth techniques
        public int MaxRetries { get; set; } = 2;            // Max probe retries
        public double JitterFactor { get; set; } = 0.0;     // Random delay factor
    }

    public static TimingProfile GetProfile(TimingLevel level)
    {
        return level switch
        {
            TimingLevel.Paranoid => new TimingProfile
            {
                ScanDelay = 5000,
                MaxParallelism = 1,
                InitialRttTimeout = 15000,
                MinRttTimeout = 1000,
                MaxRttTimeout = 30000,
                HostTimeout = 900000,
                ScanTimeout = 900000,
                EnableStealth = true,
                MaxRetries = 10,
                JitterFactor = 0.5
            },
            TimingLevel.Sneaky => new TimingProfile
            {
                ScanDelay = 15000,
                MaxParallelism = 1,
                InitialRttTimeout = 5000,
                MinRttTimeout = 500,
                MaxRttTimeout = 15000,
                HostTimeout = 600000,
                ScanTimeout = 600000,
                EnableStealth = true,
                MaxRetries = 7,
                JitterFactor = 0.3
            },
            TimingLevel.Polite => new TimingProfile
            {
                ScanDelay = 400,
                MaxParallelism = 10,
                InitialRttTimeout = 1000,
                MinRttTimeout = 100,
                MaxRttTimeout = 10000,
                HostTimeout = 300000,
                ScanTimeout = 300000,
                EnableStealth = false,
                MaxRetries = 3,
                JitterFactor = 0.1
            },
            TimingLevel.Normal => new TimingProfile
            {
                ScanDelay = 100,
                MaxParallelism = 50,
                InitialRttTimeout = 1000,
                MinRttTimeout = 100,
                MaxRttTimeout = 10000,
                HostTimeout = 300000,
                ScanTimeout = 300000,
                EnableStealth = false,
                MaxRetries = 2,
                JitterFactor = 0.05
            },
            TimingLevel.Aggressive => new TimingProfile
            {
                ScanDelay = 50,
                MaxParallelism = 100,
                InitialRttTimeout = 500,
                MinRttTimeout = 50,
                MaxRttTimeout = 5000,
                HostTimeout = 180000,
                ScanTimeout = 180000,
                EnableStealth = false,
                MaxRetries = 1,
                JitterFactor = 0.0
            },
            TimingLevel.Insane => new TimingProfile
            {
                ScanDelay = 5,
                MaxParallelism = 300,
                InitialRttTimeout = 250,
                MinRttTimeout = 25,
                MaxRttTimeout = 2500,
                HostTimeout = 60000,
                ScanTimeout = 60000,
                EnableStealth = false,
                MaxRetries = 0,
                JitterFactor = 0.0
            },
            _ => new TimingProfile()
        };
    }

    public static string GetDescription(TimingLevel level)
    {
        return level switch
        {
            TimingLevel.Paranoid => "Paranoid (T0) - Muito lento, quase indetetável. Serializado, 5s delay entre probes.",
            TimingLevel.Sneaky => "Sneaky (T1) - Lento, difícil de detetar. Serializado, 15s delay.",
            TimingLevel.Polite => "Polite (T2) - Respeita a carga da rede. 400ms delay, até 10 paralelos.",
            TimingLevel.Normal => "Normal (T3) - Padrão, equilibrado. 100ms delay, até 50 paralelos.",
            TimingLevel.Aggressive => "Aggressive (T4) - Rápido para redes modernas. 50ms delay, até 100 paralelos.",
            TimingLevel.Insane => "Insane (T5) - Muito rápido, pode sobrecarregar a rede. 5ms delay, até 300 paralelos.",
            _ => "Desconhecido"
        };
    }

    public static async Task ApplyDelayAsync(TimingProfile profile, Random? random = null)
    {
        random ??= new Random();
        
        if (profile.JitterFactor > 0)
        {
            var jitter = (int)(profile.ScanDelay * profile.JitterFactor);
            var delay = profile.ScanDelay + random.Next(-jitter, jitter);
            await Task.Delay(Math.Max(0, delay));
        }
        else
        {
            await Task.Delay(profile.ScanDelay);
        }
    }
}
