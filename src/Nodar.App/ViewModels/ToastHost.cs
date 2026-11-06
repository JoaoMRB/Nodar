using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.Input;

namespace Nodar.App.ViewModels;

/// <summary>Avisos discretos dentro da app: no máximo 4 visíveis, desaparecem sozinhos.</summary>
public sealed partial class ToastHost
{
    private const int MaxVisible = 4;

    public ObservableCollection<ToastViewModel> Items { get; } = [];

    public void Show(string title, string message, ToastKind kind)
    {
        var toast = new ToastViewModel(title, message, kind);
        Items.Add(toast);
        while (Items.Count > MaxVisible)
            Items.RemoveAt(0);

        DispatcherTimer.RunOnce(() => Items.Remove(toast), TimeSpan.FromSeconds(kind == ToastKind.Danger ? 9 : 5));
    }

    [RelayCommand]
    private void Dismiss(ToastViewModel? toast)
    {
        if (toast != null)
            Items.Remove(toast);
    }
}
