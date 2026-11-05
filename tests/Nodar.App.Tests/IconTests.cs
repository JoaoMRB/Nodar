using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Media;
using Avalonia.Threading;
using ShapePath = Avalonia.Controls.Shapes.Path;

namespace Nodar.App.Tests;

/// <summary>
/// Regressão: com Width/Height fixos, o Avalonia escalava as formas não quadradas mas encostava-as ao canto
/// superior esquerdo (telemóvel 3,5 px à esquerda, consola 5,5 px acima…). Todos os ícones têm de ficar
/// centrados no seu espaço.
/// </summary>
public class IconTests
{
    /// <summary>Todos os ícones definidos em Styles/Icons.axaml.</summary>
    private static IEnumerable<string> IconKeys()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(System.IO.Path.Combine(dir.FullName, "Nodar.sln")))
            dir = dir.Parent;
        var xaml = File.ReadAllText(System.IO.Path.Combine(dir!.FullName, "src", "Nodar.App", "Styles", "Icons.axaml"));
        return System.Text.RegularExpressions.Regex.Matches(xaml, @"x:Key=""(?<k>Icon\.[A-Za-z]+)""").Select(m => m.Groups["k"].Value);
    }

    /// <summary>Desvio (x, y) do centro da parte desenhada em relação ao centro de uma caixa de 40×40.</summary>
    private static (double X, double Y) RenderOffset(Geometry geometry, string sizeClass)
    {
        var path = new ShapePath { Data = geometry, Stroke = Brushes.White };
        path.Classes.Add("icon");
        path.Classes.Add(sizeClass);
        var window = new Window
        {
            Width = 40, Height = 40, Background = Brushes.Black,
            Content = new Border { Width = 40, Height = 40, Background = Brushes.Black, Child = path }
        };
        window.Show();
        Dispatcher.UIThread.RunJobs();
        try
        {
            var frame = window.CaptureRenderedFrame()!;
            using var buffer = frame.Lock();
            var bytes = new byte[buffer.RowBytes * buffer.Size.Height];
            Marshal.Copy(buffer.Address, bytes, 0, bytes.Length);

            int minX = int.MaxValue, minY = int.MaxValue, maxX = -1, maxY = -1;
            for (var y = 0; y < buffer.Size.Height; y++)
            for (var x = 0; x < buffer.Size.Width; x++)
                if (bytes[y * buffer.RowBytes + x * 4 + 1] > 100)
                {
                    minX = Math.Min(minX, x); maxX = Math.Max(maxX, x);
                    minY = Math.Min(minY, y); maxY = Math.Max(maxY, y);
                }

            Assert.True(maxX >= 0, "o ícone não desenhou nada");
            return ((minX + maxX) / 2.0 - 19.5, (minY + maxY) / 2.0 - 19.5);
        }
        finally
        {
            window.Close();
        }
    }

    [AvaloniaTheory]
    [InlineData("sm")]
    [InlineData("lg")]
    [InlineData("xl")]
    public void All_icons_are_centered(string sizeClass)
    {
        var keys = IconKeys().ToList();
        Assert.True(keys.Count >= 30, $"só {keys.Count} ícones encontrados");

        var offCenter = new List<string>();
        foreach (var key in keys)
        {
            var geometry = (Geometry)Application.Current!.FindResource(key)!;
            var (x, y) = RenderOffset(geometry, sizeClass);
            if (Math.Abs(x) > 1.5 || Math.Abs(y) > 1.5)
                offCenter.Add($"{key} ({x:+0.0;-0.0}, {y:+0.0;-0.0})");
        }
        Assert.Empty(offCenter);
    }
}
