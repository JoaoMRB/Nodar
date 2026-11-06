using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;

namespace Nodar.App.ViewModels;

/// <summary>Vista de Monitorizados: os dispositivos de que o utilizador quer saber quando entram ou saem.</summary>
public sealed partial class WatchlistViewModel(DeviceTracker tracker) : ObservableObject
{
    public ObservableCollection<WatchItemViewModel> Items { get; } = [];

    [ObservableProperty] private bool _hasItems;

    /// <param name="online">Os dispositivos do último scan (vazio antes do primeiro scan).</param>
    public void Update(IReadOnlyList<DeviceInfo> online)
    {
        Items.Clear();
        foreach (var w in tracker.Watchlist)
        {
            var isOnline = online.Any(d => tracker.Key(d) == tracker.Key(w.MacAddress, w.IpAddress));
            Items.Add(new WatchItemViewModel(w, isOnline, tracker.Save));
        }
        HasItems = Items.Count > 0;
    }
}
