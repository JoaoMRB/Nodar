using Microsoft.Win32;

namespace Nodar.App.Services;

/// <summary>
/// Arranque com o Windows: entrada em <c>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</c>
/// (só para o utilizador atual, sem privilégios de administrador), com <c>--minimized</c>.
/// </summary>
public static class StartupRegistration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "Nodar";
    public const string MinimizedArgument = "--minimized";

    public static string? CurrentCommand()
    {
        var path = Environment.ProcessPath;
        return path != null && Path.GetFileName(path).Equals("Nodar.exe", StringComparison.OrdinalIgnoreCase)
            ? $"\"{path}\" {MinimizedArgument}"
            : null; // ex.: a correr por "dotnet run" ou por outra ferramenta
    }

    public static bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(ValueName) is string;
    }

    /// <summary>Ativa/desativa. Devolve <c>false</c> se não foi possível (ex.: sem executável publicado).</summary>
    public static bool Set(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
            if (!enabled)
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
                return true;
            }
            var command = CurrentCommand();
            if (command == null)
                return false;
            key.SetValue(ValueName, command, RegistryValueKind.String);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Se estiver ativo mas o executável mudou de sítio, atualiza o caminho.</summary>
    public static void Refresh(bool enabled)
    {
        if (!enabled)
            return;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            var current = CurrentCommand();
            if (current != null && key?.GetValue(ValueName) as string != current)
                Set(true);
        }
        catch
        {
            // Sem acesso ao registo: ignorar.
        }
    }
}
