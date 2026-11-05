namespace Nodar.App.Services;

/// <summary>Registo de erros inesperados em <c>%LOCALAPPDATA%\Nodar\logs\</c>.</summary>
public static class CrashLog
{
    public static string Directory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nodar", "logs");

    public static string? Write(Exception ex, string context)
    {
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            var path = Path.Combine(Directory, $"erro-{DateTime.Now:yyyyMMdd}.log");
            File.AppendAllText(path, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}{Environment.NewLine}{ex}{Environment.NewLine}{Environment.NewLine}");
            return path;
        }
        catch
        {
            return null;
        }
    }
}
