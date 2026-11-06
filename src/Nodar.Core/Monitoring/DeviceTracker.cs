using System.Text.RegularExpressions;
using Nodar.Core.Models;

namespace Nodar.Core.Monitoring;

/// <summary>
/// Histórico de presença dos dispositivos e lista de monitorização, com persistência em disco.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Os dispositivos são identificados pelo MAC (o IP muda com o DHCP); sem MAC, pelo IP.</item>
/// <item>"Novo" significa nunca visto antes. No primeiro scan de sempre nada é marcado como novo
/// (é a linha de base da rede).</item>
/// <item>Um dispositivo só é dado como saído depois de falhar <see cref="MissedScansBeforeLeft"/> scans
/// seguidos: telemóveis em repouso falham respostas pontualmente e geravam alertas falsos.</item>
/// </list>
/// </remarks>
public sealed class DeviceTracker
{
    public const int MissedScansBeforeLeft = 2;
    public const string Online = "Online";
    public const string Offline = "Offline";

    private static readonly Regex MacRegex = new("^([0-9A-F]{2}:){5}[0-9A-F]{2}$", RegexOptions.Compiled);

    private readonly string _historyPath;
    private readonly string _watchlistPath;
    private readonly Func<DateTime> _now;
    private readonly Dictionary<string, DeviceHistoryEntry> _history = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<WatchedDevice> _watchlist = [];

    public DeviceTracker(string dataDirectory, Func<DateTime>? clock = null)
    {
        DataDirectory = dataDirectory;
        _historyPath = Path.Combine(dataDirectory, "history.json");
        _watchlistPath = Path.Combine(dataDirectory, "watchlist.json");
        _now = clock ?? (() => DateTime.Now);
    }

    public static string DefaultDataDirectory => NodarPaths.DataDirectory;

    public string DataDirectory { get; }

    public IReadOnlyCollection<DeviceHistoryEntry> History => _history.Values;
    public IReadOnlyList<WatchedDevice> Watchlist => _watchlist;

    /// <summary>Momento do primeiro scan de sempre (linha de base): o que já lá estava não é "novo".</summary>
    public DateTime? BaselineAt => _history.Count == 0 ? null : _history.Values.Min(e => e.FirstSeenAt ?? e.SeenAt);

    /// <summary>Visto pela primeira vez depois da linha de base e há menos de <paramref name="window"/>.</summary>
    public bool IsRecentlyNew(DeviceHistoryEntry? entry, TimeSpan window)
    {
        if (entry?.FirstSeenAt is not { } first || BaselineAt is not { } baseline)
            return false;
        return first > baseline.AddMinutes(1) && _now() - first < window;
    }

    /// <summary>Chave estável de um dispositivo: MAC normalizado ou, sem MAC, o IP.</summary>
    public static string KeyFor(string? mac, string? ip)
    {
        var normalized = (mac ?? "").Trim().ToUpperInvariant().Replace('-', ':');
        return MacRegex.IsMatch(normalized) ? normalized : "ip:" + (ip ?? "").Trim();
    }

    public static string KeyFor(DeviceInfo device) => KeyFor(device.MacAddress, device.IpAddress);

    /// <summary>
    /// MACs vistos com vários IPs ao mesmo tempo. Acontece atrás de repetidores Wi-Fi que traduzem MACs
    /// (todos os clientes do repetidor aparecem com o MAC dele): aí o MAC sozinho não identifica o dispositivo.
    /// </summary>
    private readonly HashSet<string> _sharedMacs = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Chave do dispositivo neste histórico: MAC, ou MAC@IP se o MAC for partilhado, ou o IP sem MAC.</summary>
    public string Key(string? mac, string? ip)
    {
        var key = KeyFor(mac, ip);
        return !key.StartsWith("ip:", StringComparison.Ordinal) && _sharedMacs.Contains(key) ? $"{key}@{ip}" : key;
    }

    public string Key(DeviceInfo device) => Key(device.MacAddress, device.IpAddress);
    private string Key(DeviceHistoryEntry entry) => Key(entry.MacAddress, entry.IpAddress);
    private string Key(WatchedDevice watched) => Key(watched.MacAddress, watched.IpAddress);

    public DeviceHistoryEntry? GetHistory(DeviceInfo device) =>
        _history.TryGetValue(Key(device), out var entry) ? entry : null;

    public WatchedDevice? FindWatched(string? mac, string? ip)
    {
        var key = Key(mac, ip);
        return _watchlist.FirstOrDefault(w => Key(w) == key)
               ?? _watchlist.FirstOrDefault(w => !string.IsNullOrEmpty(ip) &&
                                                 string.Equals(w.IpAddress, ip, StringComparison.OrdinalIgnoreCase) &&
                                                 !MacRegex.IsMatch((w.MacAddress ?? "").ToUpperInvariant()));
    }

    public WatchedDevice? FindWatched(DeviceInfo device) => FindWatched(device.MacAddress, device.IpAddress);

    // ---------------------------------------------------------------- persistência

    public void Load()
    {
        MigrateLegacyData();
        _history.Clear();
        _watchlist.Clear();
        _sharedMacs.Clear();

        var entries = JsonStore.Read<List<DeviceHistoryEntry>>(_historyPath) ?? [];
        foreach (var entry in entries.Where(e => e.SharedMac))
            _sharedMacs.Add(KeyFor(entry.MacAddress, entry.IpAddress));

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.IpAddress) && string.IsNullOrWhiteSpace(entry.MacAddress))
                continue;
            entry.FirstSeenAt ??= entry.Events.Count > 0 ? entry.Events.Min(e => e.Timestamp) : entry.SeenAt;

            // Ficheiros antigos eram indexados por IP: juntar entradas do mesmo MAC.
            var key = Key(entry);
            if (_history.TryGetValue(key, out var existing))
            {
                existing.Events.AddRange(entry.Events);
                existing.Events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
                if (entry.SeenAt > existing.SeenAt)
                {
                    existing.SeenAt = entry.SeenAt;
                    existing.IpAddress = entry.IpAddress;
                    existing.Status = entry.Status;
                }
                if (entry.FirstSeenAt < existing.FirstSeenAt)
                    existing.FirstSeenAt = entry.FirstSeenAt;
            }
            else
            {
                _history[key] = entry;
            }
        }

        _watchlist.AddRange(JsonStore.Read<List<WatchedDevice>>(_watchlistPath) ?? []);
    }

    public void Save()
    {
        JsonStore.Write(_historyPath, _history.Values.OrderBy(e => e.IpAddress, StringComparer.OrdinalIgnoreCase).ToList());
        JsonStore.Write(_watchlistPath, _watchlist);
    }

    // ---------------------------------------------------------------- scans

    /// <summary>Aplica o resultado de um scan completo ao histórico e devolve o que mudou.</summary>
    public TrackerUpdate ApplyScan(IReadOnlyList<DeviceInfo> devices)
    {
        var now = _now();
        var isBaseline = _history.Count == 0;
        var update = new TrackerUpdate();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        MarkSharedMacs(devices);

        foreach (var device in devices)
        {
            var key = Key(device);
            if (!seenKeys.Add(key))
                continue;

            if (!_history.TryGetValue(key, out var entry))
            {
                entry = new DeviceHistoryEntry
                {
                    FirstSeenAt = now,
                    Status = Online,
                    SharedMac = _sharedMacs.Contains(KeyFor(device))
                };
                _history[key] = entry;
                entry.Events.Add(new DeviceHistoryEvent { EventType = DeviceHistoryEventType.Seen, Timestamp = now, Status = Online });
                if (!isBaseline)
                    update.NewDevices.Add(device);
                NotifyIfWatched(device, entering: true, update);
            }
            else if (entry.Status == Offline)
            {
                entry.Events.Add(new DeviceHistoryEvent { EventType = DeviceHistoryEventType.Seen, Timestamp = now, Status = Online });
                update.Returned.Add(device);
                NotifyIfWatched(device, entering: true, update);
            }

            entry.IpAddress = device.IpAddress;
            entry.MacAddress = device.MacAddress;
            if (!string.IsNullOrWhiteSpace(device.Hostname))
                entry.Hostname = device.Hostname;
            if (!string.IsNullOrWhiteSpace(device.Vendor) && device.Vendor != "Desconhecido")
                entry.Vendor = device.Vendor;
            entry.DeviceType = device.DeviceType;
            if (!string.IsNullOrWhiteSpace(device.FriendlyName))
                entry.FriendlyName = device.FriendlyName;
            if (!string.IsNullOrWhiteSpace(device.Model))
                entry.Model = device.Model;
            entry.Status = Online;
            entry.SeenAt = now;
            entry.MissedScans = 0;
        }

        foreach (var (key, entry) in _history)
        {
            if (seenKeys.Contains(key) || entry.Status == Offline)
                continue;

            entry.MissedScans++;
            if (entry.MissedScans < MissedScansBeforeLeft)
                continue;

            entry.Status = Offline;
            entry.LastLeftAt = now;
            entry.Events.Add(new DeviceHistoryEvent { EventType = DeviceHistoryEventType.Left, Timestamp = now, Status = Offline });

            var watched = FindWatched(entry.MacAddress, entry.IpAddress);
            if (watched is { NotifyOnLeave: true })
                update.WatchedLeft.Add(new WatchedEvent(watched, entry.Hostname, entry.IpAddress));
        }

        Save();
        return update;
    }

    /// <summary>
    /// Deteta MACs com vários IPs neste scan. A entrada antiga desse MAC (se existir) passa a ser do IP que
    /// tinha, e cada IP fica com o seu histórico.
    /// </summary>
    private void MarkSharedMacs(IReadOnlyList<DeviceInfo> devices)
    {
        var shared = devices
            .Select(d => (Mac: KeyFor(d.MacAddress, d.IpAddress), d.IpAddress))
            .Where(x => !x.Mac.StartsWith("ip:", StringComparison.Ordinal))
            .GroupBy(x => x.Mac, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Select(x => x.IpAddress).Distinct().Count() > 1)
            .Select(g => g.Key);

        foreach (var mac in shared)
        {
            if (!_sharedMacs.Add(mac))
                continue;
            if (_history.Remove(mac, out var existing))
            {
                existing.SharedMac = true;
                _history[$"{mac}@{existing.IpAddress}"] = existing;
            }
        }
    }

    private void NotifyIfWatched(DeviceInfo device, bool entering, TrackerUpdate update)
    {
        var watched = FindWatched(device);
        if (watched is { NotifyOnEnter: true } && entering)
            update.WatchedArrived.Add(new WatchedEvent(watched, device.DisplayName, device.IpAddress));
    }

    /// <summary>Dispositivos conhecidos que não estão online (para a vista "mostrar offline").</summary>
    public IEnumerable<DeviceHistoryEntry> OfflineEntries() =>
        _history.Values.Where(e => e.Status == Offline).OrderByDescending(e => e.LastLeftAt ?? e.SeenAt);

    // ---------------------------------------------------------------- monitorização

    public WatchedDevice Watch(DeviceInfo device, string? name = null, bool notifyOnEnter = true, bool notifyOnLeave = true)
    {
        var existing = FindWatched(device);
        if (existing != null)
        {
            existing.Name = string.IsNullOrWhiteSpace(name) ? existing.Name : name.Trim();
            existing.NotifyOnEnter = notifyOnEnter;
            existing.NotifyOnLeave = notifyOnLeave;
            Save();
            return existing;
        }

        var watched = new WatchedDevice
        {
            IpAddress = device.IpAddress,
            MacAddress = device.MacAddress,
            Name = string.IsNullOrWhiteSpace(name) ? device.DisplayName : name.Trim(),
            NotifyOnEnter = notifyOnEnter,
            NotifyOnLeave = notifyOnLeave,
            AddedAt = _now()
        };
        _watchlist.Add(watched);
        Save();
        return watched;
    }

    public bool Unwatch(WatchedDevice watched)
    {
        var removed = _watchlist.Remove(watched);
        if (removed)
            Save();
        return removed;
    }

    // ---------------------------------------------------------------- utilitários

    /// <summary>
    /// Copia o histórico e a lista de monitorização da versão "Network Watcher Pro", que os guardava numa
    /// pasta dependente do nome do produto e da versão (%LOCALAPPDATA%\NetworkScanner\...\NetworkWatcherPro).
    /// </summary>
    private void MigrateLegacyData()
    {
        try
        {
            var legacyRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkScanner");
            if (!Directory.Exists(legacyRoot) || DataDirectory != DefaultDataDirectory)
                return;

            Directory.CreateDirectory(DataDirectory);
            foreach (var fileName in new[] { "history.json", "watchlist.json" })
            {
                var target = Path.Combine(DataDirectory, fileName);
                if (File.Exists(target))
                    continue;

                var newest = Directory.EnumerateFiles(legacyRoot, fileName, SearchOption.AllDirectories)
                    .Where(f => Path.GetFileName(Path.GetDirectoryName(f)) == "NetworkWatcherPro")
                    .OrderByDescending(File.GetLastWriteTimeUtc)
                    .FirstOrDefault();
                if (newest != null)
                    File.Copy(newest, target);
            }
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, "Migrar dados da versão antiga"))
        {
            // Migração opcional.
        }
    }

}

public sealed record WatchedEvent(WatchedDevice Watched, string DeviceName, string IpAddress);

public sealed class TrackerUpdate
{
    /// <summary>Dispositivos que nunca tinham sido vistos.</summary>
    public List<DeviceInfo> NewDevices { get; } = [];

    /// <summary>Dispositivos já conhecidos que estavam offline e voltaram à rede neste scan.</summary>
    public List<DeviceInfo> Returned { get; } = [];
    public List<WatchedEvent> WatchedArrived { get; } = [];
    public List<WatchedEvent> WatchedLeft { get; } = [];
}
