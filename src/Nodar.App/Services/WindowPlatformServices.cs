using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace Nodar.App.Services;

/// <summary>Operações que precisam da janela (diálogos, área de transferência, browser).</summary>
public interface IPlatformServices
{
    Task<string?> PickSaveFileAsync(string title, string suggestedName, string extension, string description);
    Task CopyToClipboardAsync(string text);
    void OpenUrl(string url);
    void FlashWindow();

    /// <summary>A janela está visível e em primeiro plano (o utilizador vê os avisos dentro da app).</summary>
    bool IsUserLooking { get; }

    /// <summary>Notificação do Windows (central de notificações). Devolve <c>false</c> se não foi possível.</summary>
    bool NotifySystem(string title, string message);
}

public sealed class WindowPlatformServices(Window window) : IPlatformServices
{
    /// <summary>Ícone da bandeja (definido pela App depois de criado).</summary>
    public WindowsTray? Tray { get; set; }

    public bool IsUserLooking => window.IsVisible && window.IsActive && window.WindowState != WindowState.Minimized;

    public bool NotifySystem(string title, string message) => Tray?.Notify(title, message) ?? false;

    public async Task<string?> PickSaveFileAsync(string title, string suggestedName, string extension, string description)
    {
        var file = await window.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = extension,
            ShowOverwritePrompt = true,
            FileTypeChoices = [new FilePickerFileType(description) { Patterns = [$"*.{extension}"] }]
        });
        return file?.TryGetLocalPath();
    }

    public async Task CopyToClipboardAsync(string text)
    {
        if (window.Clipboard != null)
            await window.Clipboard.SetTextAsync(text);
    }

    public void OpenUrl(string url)
    {
        // Só ligações https (as únicas que a app gera: páginas da NVD).
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return;
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            // Sem browser predefinido.
        }
    }

    /// <summary>Não rouba o foco: quem avisa com a janela escondida são as notificações do Windows.</summary>
    public void FlashWindow()
    {
    }
}
