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
}

public sealed class WindowPlatformServices(Window window) : IPlatformServices
{
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

    public void FlashWindow()
    {
        if (!window.IsActive)
            window.Activate();
    }
}
