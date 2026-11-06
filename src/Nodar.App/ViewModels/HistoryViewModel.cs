using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;

namespace Nodar.App.ViewModels;

/// <summary>Vista de Histórico: todos os dispositivos já vistos e os últimos eventos (entradas e saídas).</summary>
public sealed partial class HistoryViewModel(DeviceTracker tracker) : ObservableObject
{
    private const int MaxRecentEvents = 40;

    public ObservableCollection<HistoryEventViewModel> RecentEvents { get; } = [];
    public ObservableCollection<DeviceItemViewModel> KnownDevices { get; } = [];

    [ObservableProperty] private bool _hasHistory;

    /// <param name="devices">Os dispositivos da lista: os que estão online reaproveitam os seus dados completos.</param>
    public void Update(IReadOnlyList<DeviceItemViewModel> devices)
    {
        RecentEvents.Clear();
        KnownDevices.Clear();

        var onlineKeys = devices.Where(d => d.IsOnline)
            .GroupBy(d => d.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        foreach (var entry in tracker.History.OrderByDescending(e => e.Status == DeviceTracker.Online).ThenByDescending(e => e.SeenAt))
        {
            var device = FromHistory(entry);
            var key = tracker.Key(device);
            KnownDevices.Add(onlineKeys.TryGetValue(key, out var online)
                ? online
                : new DeviceItemViewModel(device, entry, key, false, entry.Status == DeviceTracker.Online, tracker.FindWatched(device) != null));
        }

        foreach (var e in tracker.History
                     .SelectMany(h => h.Events.Select(ev => (ev, name: NameFor(h))))
                     .OrderByDescending(x => x.ev.Timestamp)
                     .Take(MaxRecentEvents))
            RecentEvents.Add(new HistoryEventViewModel(e.ev, e.name));

        HasHistory = RecentEvents.Count > 0;
    }

    /// <summary>Reconstrói um dispositivo (offline) a partir do que o histórico guardou dele.</summary>
    internal static DeviceInfo FromHistory(DeviceHistoryEntry e) => new()
    {
        IpAddress = e.IpAddress,
        MacAddress = e.MacAddress,
        Hostname = e.Hostname,
        FriendlyName = e.FriendlyName,
        Model = e.Model,
        Vendor = e.Vendor,
        DeviceType = e.DeviceType,
        Status = DeviceTracker.Offline,
        LastSeen = e.SeenAt
    };

    private static string NameFor(DeviceHistoryEntry h) =>
        !string.IsNullOrWhiteSpace(h.FriendlyName) ? h.FriendlyName :
        !string.IsNullOrWhiteSpace(h.Hostname) ? h.Hostname.Split('.')[0] :
        !Visuals.IsUnknownVendor(h.Vendor) ? Visuals.VendorLabel(h.Vendor) : h.IpAddress;
}
