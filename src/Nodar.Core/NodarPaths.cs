namespace Nodar.Core;

/// <summary>
/// Onde o Nodar guarda os dados (histórico, definições, cache, logs).
/// Por omissão <c>%LOCALAPPDATA%\Nodar</c>; a variável de ambiente <c>NODAR_DATA_DIR</c> muda-o
/// (usado pelos testes da interface para nunca tocarem nos dados reais de quem os corre).
/// </summary>
public static class NodarPaths
{
    public const string EnvironmentVariable = "NODAR_DATA_DIR";

    public static string DataDirectory =>
        Environment.GetEnvironmentVariable(EnvironmentVariable) is { Length: > 0 } custom
            ? custom
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Nodar");

    public static string CacheDirectory => Path.Combine(DataDirectory, "cache");
    public static string SettingsFile => Path.Combine(DataDirectory, "settings.json");
}
