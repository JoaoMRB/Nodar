namespace Nodar.App.Services;

/// <summary>Registo de erros inesperados em <c>%LOCALAPPDATA%\Nodar\logs\</c>.</summary>
public static class CrashLog
{
    public static string Directory =>
        Path.Combine(Nodar.Core.NodarPaths.DataDirectory, "logs");

    public static string? Write(Exception ex, string context)
    {
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            var path = Path.Combine(Directory, $"erro-{DateTime.Now:yyyyMMdd}.log");
            File.AppendAllText(path, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}{Environment.NewLine}{ex}{Environment.NewLine}{Environment.NewLine}");
            return path;
        }
        catch (Exception logError) when (logError is IOException or UnauthorizedAccessException)
        {
            // O registo é o último recurso: se nem ele consegue escrever (disco cheio, sem permissões),
            // não há onde dar o erro, e falhar aqui só causaria um segundo erro.
            System.Diagnostics.Debug.WriteLine($"[Nodar] Não foi possível escrever o registo: {logError.Message}");
            return null;
        }
    }
}
