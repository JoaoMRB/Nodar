using System.Text.Json;
using System.Text.Json.Nodes;

namespace Nodar.Core.Settings;

/// <summary>
/// Preferências do utilizador em <c>%LOCALAPPDATA%\Nodar\settings.json</c>.
/// O mesmo ficheiro guarda a chave da NVD (<c>nvdApiKey</c>); ao gravar, as chaves desconhecidas são preservadas.
/// </summary>
public sealed class AppSettings
{
    public bool DeepScan { get; set; }
    public bool PortScan { get; set; } = true;
    public bool OsDetection { get; set; }
    public bool ServiceDetection { get; set; } = true;
    public bool VulnerabilityScan { get; set; } = true;
    public bool AutoRefresh { get; set; } = true;
    public int RefreshIntervalSeconds { get; set; } = 120;
    public bool ShowOffline { get; set; } = true;

    /// <summary>Notificações do Windows quando a janela não está à vista.</summary>
    public bool WindowsNotifications { get; set; } = true;
    /// <summary>Fechar a janela deixa o Nodar a correr na bandeja (área de notificação).</summary>
    public bool CloseToTray { get; set; } = true;
    /// <summary>Arrancar com o Windows, minimizado na bandeja.</summary>
    public bool StartWithWindows { get; set; }
    /// <summary>Idioma da interface: "auto" (o do Windows), "pt" ou "en".</summary>
    public string Language { get; set; } = "auto";
    /// <summary>Já foi mostrado o aviso de que o Nodar continua na bandeja ao fechar.</summary>
    public bool TrayHintShown { get; set; }

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static string DefaultPath =>
        NodarPaths.SettingsFile;

    public static AppSettings Load(string? path = null)
    {
        path ??= DefaultPath;
        try
        {
            if (File.Exists(path))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), Options) ?? new AppSettings();
        }
        catch (JsonException ex)
        {
            NodarLog.CorruptFile(path, ex); // ficheiro inválido: valores por omissão, com cópia do original
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, "Ler as definições"))
        {
            // Ficheiro bloqueado ou sem permissões: valores por omissão.
        }
        return new AppSettings();
    }

    public void Save(string? path = null)
    {
        path ??= DefaultPath;
        try
        {
            JsonObject root;
            try
            {
                root = File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject() : new JsonObject();
            }
            catch (JsonException ex)
            {
                NodarLog.CorruptFile(path, ex); // não perder o que lá estava (ex.: a chave da NVD)
                root = new JsonObject();
            }

            var mine = JsonSerializer.SerializeToNode(this, Options)!.AsObject();
            foreach (var (key, value) in mine)
                root[key] = value?.DeepClone();

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            File.WriteAllText(temp, root.ToJsonString(Options));
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, "Gravar as definições"))
        {
            // Não conseguir gravar preferências não deve interromper a app.
        }
    }
}
