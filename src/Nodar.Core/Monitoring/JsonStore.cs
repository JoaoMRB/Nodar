using System.Text.Json;

namespace Nodar.Core.Monitoring;

/// <summary>
/// Leitura e gravação dos pequenos ficheiros de dados da app (histórico, monitorizados, router conhecido…).
/// A gravação é atómica (ficheiro temporário + troca) e um ficheiro corrompido nunca se perde: guarda-se uma cópia.
/// </summary>
internal static class JsonStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static T? Read<T>(string path)
    {
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Options) : default;
        }
        catch (JsonException ex)
        {
            // Ficheiro corrompido: começa vazio em vez de impedir o arranque, mas guarda uma cópia, porque a
            // próxima gravação apagaria os dados.
            NodarLog.CorruptFile(path, ex);
            return default;
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, $"Ler {Path.GetFileName(path)}"))
        {
            return default; // ficheiro bloqueado ou sem permissões
        }
    }

    public static void Write<T>(string path, T value)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(value, Options));
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (NodarLog.Swallow(ex, $"Gravar {Path.GetFileName(path)}"))
        {
            // Falhar a gravação não deve interromper o scan.
        }
    }
}
