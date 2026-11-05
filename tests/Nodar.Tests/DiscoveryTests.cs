using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using Nodar.Core.Services;

namespace Nodar.Tests;

public class NeighborDiscoveryTests
{
    [Fact]
    public void Host_range_of_a_23_covers_both_halves()
    {
        var range = NeighborDiscovery.HostRange("192.168.1.16", "255.255.254.0");
        Assert.Equal(510, range.Count);
        Assert.Equal("192.168.0.1", range[0]);
        Assert.Equal("192.168.1.254", range[^1]);
        Assert.Contains("192.168.1.34", range);   // antes ficava fora do varrimento "rápido"
        Assert.Contains("192.168.0.200", range);
    }

    [Fact]
    public void Huge_networks_use_the_nearest_addresses()
    {
        var range = NeighborDiscovery.HostRange("10.0.50.10", "255.255.0.0");
        var nearest = NeighborDiscovery.NearestAddresses(range, "10.0.50.10", 1024);
        Assert.Equal(1024, nearest.Count);
        Assert.Contains("10.0.50.11", nearest);
        Assert.Contains("10.0.49.200", nearest);
        Assert.DoesNotContain("10.0.200.1", nearest);
    }

    [Theory]
    [InlineData("1A:00:00:00:00:01", true)]   // iPhone/Mac com endereço privado
    [InlineData("5A:00:00:00:00:01", true)]
    [InlineData("D0:CF:0E:00:00:01", false)]  // MAC de fabricante
    [InlineData("44:87:63:00:00:01", false)]
    [InlineData("", false)]
    public void Detects_private_randomized_macs(string mac, bool expected) =>
        Assert.Equal(expected, NeighborDiscovery.IsRandomizedMac(mac));

    [Fact]
    public void Reading_the_neighbor_table_does_not_throw()
    {
        var table = NeighborDiscovery.ReadNeighborTable();
        Assert.All(table, n => Assert.Equal(17, n.Mac.Length));
    }
}

public sealed class SharedMacTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-shared-" + Guid.NewGuid().ToString("N"));
    private DateTime _now = new(2026, 11, 5, 10, 0, 0);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private DeviceTracker Create() { var t = new DeviceTracker(_dir, () => _now); t.Load(); return t; }
    private static DeviceInfo Dev(string ip, string mac) => new() { IpAddress = ip, MacAddress = mac };

    [Fact]
    public void Devices_behind_a_repeater_sharing_a_mac_stay_separate()
    {
        var t = Create();
        t.ApplyScan([Dev("192.168.1.10", "48:A4:FD:00:00:01")]);
        t.ApplyScan([Dev("192.168.1.10", "48:A4:FD:00:00:01"), Dev("192.168.1.89", "48:A4:FD:00:00:01")]);

        Assert.Equal(2, t.History.Count);
        Assert.NotEqual(t.Key(Dev("192.168.1.10", "48:A4:FD:00:00:01")), t.Key(Dev("192.168.1.89", "48:A4:FD:00:00:01")));
        // A entrada antiga manteve-se com o IP que tinha (não é "nova")
        Assert.Equal(new DateTime(2026, 11, 5, 10, 0, 0), t.GetHistory(Dev("192.168.1.10", "48:A4:FD:00:00:01"))!.FirstSeenAt);
    }

    [Fact]
    public void Shared_mac_knowledge_survives_restart()
    {
        var t = Create();
        t.ApplyScan([Dev("192.168.1.10", "48:A4:FD:00:00:01"), Dev("192.168.1.89", "48:A4:FD:00:00:01")]);

        var reloaded = Create();
        Assert.Equal(2, reloaded.History.Count);
        Assert.NotNull(reloaded.GetHistory(Dev("192.168.1.89", "48:A4:FD:00:00:01")));
    }

    [Fact]
    public void Normal_mac_still_follows_ip_changes()
    {
        var t = Create();
        t.ApplyScan([Dev("192.168.1.20", "AA:BB:CC:00:00:01")]);
        t.ApplyScan([Dev("192.168.1.21", "AA:BB:CC:00:00:01")]);
        Assert.Single(t.History);
    }
}
