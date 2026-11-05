using System.Text.Json;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;

namespace Nodar.Tests;

public sealed class DeviceTrackerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-tracker-" + Guid.NewGuid().ToString("N"));
    private DateTime _now = new(2026, 11, 5, 10, 0, 0);

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private DeviceTracker Create()
    {
        var t = new DeviceTracker(_dir, () => _now);
        t.Load();
        return t;
    }

    private static DeviceInfo Dev(string ip, string mac, string host = "") =>
        new() { IpAddress = ip, MacAddress = mac, Hostname = host };

    private static readonly DeviceInfo Phone = Dev("192.168.1.20", "AA:BB:CC:00:00:01", "iphone");
    private static readonly DeviceInfo Tv = Dev("192.168.1.30", "AA:BB:CC:00:00:02", "tv");

    [Fact]
    public void First_scan_is_baseline_and_flags_nothing_as_new()
    {
        var update = Create().ApplyScan([Phone, Tv]);
        Assert.Empty(update.NewDevices);
    }

    [Fact]
    public void Device_never_seen_before_is_new()
    {
        var t = Create();
        t.ApplyScan([Phone]);
        var update = t.ApplyScan([Phone, Tv]);
        Assert.Equal("192.168.1.30", Assert.Single(update.NewDevices).IpAddress);
    }

    [Fact]
    public void Returning_device_is_not_new()
    {
        var t = Create();
        t.ApplyScan([Phone, Tv]);
        t.ApplyScan([Phone]);
        t.ApplyScan([Phone]); // Tv sai
        var update = t.ApplyScan([Phone, Tv]);
        Assert.Empty(update.NewDevices);
    }

    [Fact]
    public void Same_mac_with_new_ip_is_same_device()
    {
        var t = Create();
        t.ApplyScan([Phone]);
        var update = t.ApplyScan([Dev("192.168.1.99", "aa-bb-cc-00-00-01")]);
        Assert.Empty(update.NewDevices);
        Assert.Single(t.History);
        Assert.Equal("192.168.1.99", t.History.Single().IpAddress);
    }

    [Fact]
    public void Device_goes_offline_only_after_two_missed_scans()
    {
        var t = Create();
        t.ApplyScan([Phone, Tv]);

        t.ApplyScan([Tv]);
        Assert.Equal(DeviceTracker.Online, t.GetHistory(Phone)!.Status); // falha pontual

        _now = _now.AddMinutes(1);
        t.ApplyScan([Tv]);
        var entry = t.GetHistory(Phone)!;
        Assert.Equal(DeviceTracker.Offline, entry.Status);
        Assert.Equal(_now, entry.LastLeftAt);
        Assert.Equal(DeviceHistoryEventType.Left, entry.Events.Last().EventType);
    }

    [Fact]
    public void Single_miss_then_seen_again_does_not_create_events()
    {
        var t = Create();
        t.ApplyScan([Phone]);
        t.ApplyScan([]);
        t.ApplyScan([Phone]);
        Assert.Single(t.GetHistory(Phone)!.Events);
    }

    [Fact]
    public void Watched_device_arrival_and_departure_are_reported()
    {
        var t = Create();
        t.ApplyScan([Phone, Tv]);
        t.Watch(Phone, "Telemóvel da Ana");

        t.ApplyScan([Tv]);
        var left = t.ApplyScan([Tv]);
        Assert.Equal("Telemóvel da Ana", Assert.Single(left.WatchedLeft).Watched.Name);

        var back = t.ApplyScan([Phone, Tv]);
        Assert.Equal("Telemóvel da Ana", Assert.Single(back.WatchedArrived).Watched.Name);
    }

    [Fact]
    public void Notification_preferences_are_respected()
    {
        var t = Create();
        t.ApplyScan([Phone]);
        t.Watch(Phone, notifyOnEnter: false, notifyOnLeave: false);
        t.ApplyScan([]);
        Assert.Empty(t.ApplyScan([]).WatchedLeft);
        Assert.Empty(t.ApplyScan([Phone]).WatchedArrived);
    }

    [Fact]
    public void History_and_watchlist_persist()
    {
        var t = Create();
        t.ApplyScan([Phone, Tv]);
        t.Watch(Tv, "Sala");

        var reloaded = Create();
        Assert.Equal(2, reloaded.History.Count);
        Assert.Equal("Sala", Assert.Single(reloaded.Watchlist).Name);
        Assert.NotNull(reloaded.FindWatched(Tv));
    }

    [Fact]
    public void Watch_twice_updates_instead_of_duplicating()
    {
        var t = Create();
        t.Watch(Phone, "A");
        t.Watch(Phone, "B");
        Assert.Equal("B", Assert.Single(t.Watchlist).Name);
        Assert.True(t.Unwatch(t.Watchlist[0]));
        Assert.Empty(t.Watchlist);
    }

    [Fact]
    public void Legacy_ip_keyed_history_is_merged_by_mac()
    {
        Directory.CreateDirectory(_dir);
        var legacy = new List<DeviceHistoryEntry>
        {
            new() { IpAddress = "192.168.1.20", MacAddress = "AA:BB:CC:00:00:01", Status = "Offline", SeenAt = _now.AddDays(-2),
                    Events = [new() { EventType = DeviceHistoryEventType.Seen, Timestamp = _now.AddDays(-3) }] },
            new() { IpAddress = "192.168.1.21", MacAddress = "AA:BB:CC:00:00:01", Status = "Online", SeenAt = _now.AddDays(-1),
                    Events = [new() { EventType = DeviceHistoryEventType.Seen, Timestamp = _now.AddDays(-1) }] },
        };
        File.WriteAllText(Path.Combine(_dir, "history.json"), JsonSerializer.Serialize(legacy));

        var t = Create();
        var entry = Assert.Single(t.History);
        Assert.Equal("192.168.1.21", entry.IpAddress);
        Assert.Equal(2, entry.Events.Count);
        Assert.Equal(_now.AddDays(-3), entry.FirstSeenAt);
    }

    [Fact]
    public void Corrupt_files_do_not_prevent_startup()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "history.json"), "{ not json");
        var t = Create();
        Assert.Empty(t.History);
    }

    [Theory]
    [InlineData("aa:bb:cc:dd:ee:ff", "1.1.1.1", "AA:BB:CC:DD:EE:FF")]
    [InlineData("AA-BB-CC-DD-EE-FF", "1.1.1.1", "AA:BB:CC:DD:EE:FF")]
    [InlineData("—", "1.1.1.1", "ip:1.1.1.1")]
    [InlineData("", "1.1.1.1", "ip:1.1.1.1")]
    public void Key_prefers_mac(string mac, string ip, string expected) =>
        Assert.Equal(expected, DeviceTracker.KeyFor(mac, ip));
}

public sealed class DeviceTrackerNewnessTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-tracker-" + Guid.NewGuid().ToString("N"));
    private DateTime _now = new(2026, 11, 5, 10, 0, 0);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public void Baseline_devices_are_not_recently_new_but_later_ones_are_for_24h()
    {
        var t = new DeviceTracker(_dir, () => _now);
        t.Load();
        var a = new Nodar.Core.Models.DeviceInfo { IpAddress = "10.0.0.2", MacAddress = "AA:AA:AA:AA:AA:01" };
        var b = new Nodar.Core.Models.DeviceInfo { IpAddress = "10.0.0.3", MacAddress = "AA:AA:AA:AA:AA:02" };

        t.ApplyScan([a]);
        Assert.False(t.IsRecentlyNew(t.GetHistory(a), TimeSpan.FromHours(24)));

        _now = _now.AddHours(2);
        t.ApplyScan([a, b]);
        Assert.True(t.IsRecentlyNew(t.GetHistory(b), TimeSpan.FromHours(24)));

        _now = _now.AddHours(25);
        Assert.False(t.IsRecentlyNew(t.GetHistory(b), TimeSpan.FromHours(24)));
    }
}
