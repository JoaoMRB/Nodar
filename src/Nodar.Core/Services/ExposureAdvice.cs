namespace Nodar.Core.Services;

/// <summary>Que serviços não deviam estar abertos para a internet, e como se chamam as portas mais comuns.</summary>
public static class ExposureAdvice
{
    /// <summary>
    /// Serviços de acesso remoto, partilha de ficheiros, bases de dados e câmaras: abertos para a internet são
    /// alvo constante de ataques automáticos (palavras-passe fracas, falhas conhecidas).
    /// </summary>
    private static readonly Dictionary<int, string> Sensitive = new()
    {
        [21] = "FTP",
        [22] = "SSH",
        [23] = "Telnet",
        [135] = "MSRPC",
        [139] = "NetBIOS",
        [445] = "SMB",
        [554] = "RTSP",
        [1433] = "MSSQL",
        [3306] = "MySQL",
        [3389] = "RDP",
        [5432] = "PostgreSQL",
        [5900] = "VNC",
        [6379] = "Redis",
        [8554] = "RTSP",
        [27017] = "MongoDB"
    };

    /// <summary>
    /// Merece uma notificação do Windows (a que aparece mesmo com a janela fechada)? Jogos e chamadas de vídeo
    /// (Parsec, consolas…) pedem portas temporárias ao router e renovam-nas enquanto correm: avisar de cada vez
    /// que abrem seria ruído. Ficam na app, mas só as permanentes ou as sensíveis interrompem o utilizador.
    /// </summary>
    public static bool WorthSystemNotice(Models.PortMapping mapping) =>
        mapping.LeaseSeconds == 0 || SensitiveService(mapping.InternalPort) != null;

    /// <summary>Nome do serviço se a porta de destino for sensível (<c>null</c> se não for).</summary>
    public static string? SensitiveService(int port) => Sensitive.GetValueOrDefault(port);

    /// <summary>Nome conhecido da porta (HTTP, SSH…), ou <c>null</c>.</summary>
    public static string? PortName(int port) =>
        Sensitive.GetValueOrDefault(port) ?? ServiceDetectionService.WellKnownName(port);
}
