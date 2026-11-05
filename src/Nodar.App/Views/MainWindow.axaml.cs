using Avalonia.Controls;
using Avalonia.Media;
using Nodar.App.ViewModels;

namespace Nodar.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Opened += OnOpened;
    }

    private async void OnOpened(object? sender, EventArgs e)
    {
        // Sem Acrylic/Mica (ex.: transparência desligada no Windows), o tom passa a sólido para manter o contraste.
        if (ActualTransparencyLevel == WindowTransparencyLevel.None)
            Tint.Background = new SolidColorBrush(Color.Parse("#FF0B0D14"));

        if (DataContext is MainViewModel vm)
            await vm.StartAsync();
    }
}
