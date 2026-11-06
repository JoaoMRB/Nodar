namespace Nodar.Core.Models;

/// <summary>Como correu a leitura das portas abertas pelo router (UPnP).</summary>
public enum UpnpStatus
{
    /// <summary>O router não anunciou UPnP (ou não tem ligação WAN): é o estado mais seguro.</summary>
    NotFound,
    /// <summary>O router tem UPnP mas recusa listar os redirecionamentos.</summary>
    ListingRefused,
    /// <summary>O router não respondeu a tempo ou respondeu algo ilegível.</summary>
    Failed,
    /// <summary>Lista lida (pode estar vazia).</summary>
    Ok
}

/// <summary>Um redirecionamento de porta pedido ao router por UPnP (internet → dispositivo da rede).</summary>
public sealed class PortMapping
{
    /// <summary>"TCP" ou "UDP".</summary>
    public string Protocol { get; init; } = "TCP";
    public int ExternalPort { get; init; }
    public string InternalClient { get; init; } = "";
    public int InternalPort { get; init; }

    /// <summary>Descrição dada pela aplicação que o pediu (ex.: "Skype", "PlayStation").</summary>
    public string Description { get; init; } = "";
    public bool Enabled { get; init; } = true;

    /// <summary>Duração restante em segundos (0 = permanente).</summary>
    public int LeaseSeconds { get; init; }

    /// <summary>Vazio = qualquer endereço da internet; preenchido = só esse.</summary>
    public string RemoteHost { get; init; } = "";

    public bool OpenToWholeInternet => Enabled && (RemoteHost.Length == 0 || RemoteHost == "0.0.0.0");

    /// <summary>Identifica o redirecionamento entre scans.</summary>
    public string Key => $"{Protocol}:{ExternalPort}>{InternalClient}:{InternalPort}";
}

public sealed class UpnpReport
{
    public UpnpStatus Status { get; init; }

    /// <summary>Endereço que o router diz ter na internet (pode ser privado, se houver CGNAT).</summary>
    public string? ExternalIp { get; init; }
    public List<PortMapping> Mappings { get; init; } = [];

    /// <summary>A lista foi cortada ao limite (um router a devolver entradas sem fim).</summary>
    public bool Truncated { get; init; }
}

public enum InternetCheckStatus
{
    /// <summary>O Shodan tem dados deste endereço.</summary>
    Ok,
    /// <summary>O Shodan não tem nada deste endereço (não viu serviços abertos).</summary>
    NothingSeen,
    /// <summary>O endereço da rede não é público (CGNAT ou duplo NAT): não há nada a consultar.</summary>
    NotPublic,
    /// <summary>Sem ligação ou o serviço não respondeu.</summary>
    Failed
}

/// <summary>O que a internet vê do endereço público, segundo o Shodan InternetDB.</summary>
public sealed class InternetExposure
{
    public InternetCheckStatus Status { get; init; }
    public string Ip { get; init; } = "";
    public List<int> Ports { get; init; } = [];

    /// <summary>CVEs que o Shodan associa aos serviços vistos.</summary>
    public List<string> Vulns { get; init; } = [];
    public List<string> Hostnames { get; init; } = [];
    public List<string> Tags { get; init; } = [];
    public DateTime CheckedAt { get; init; } = DateTime.Now;
}

/// <summary>O MAC que responde pelo router mudou: pode ser um router novo, outra rede ou alguém a fazer-se passar por ele.</summary>
/// <param name="GatewayIp">Endereço do router.</param>
/// <param name="KnownMac">MAC que o router tinha até aqui.</param>
/// <param name="NewMac">MAC com que responde agora.</param>
/// <param name="OtherDeviceIp">
/// Outro dispositivo da rede com exatamente o mesmo MAC. É o rasto típico de ARP spoofing: o atacante responde
/// pelo router com o MAC da sua própria placa, que continua visível com o seu IP.
/// </param>
public sealed record GatewayAlert(string GatewayIp, string KnownMac, string NewMac, string? OtherDeviceIp)
{
    /// <summary>Há outro dispositivo com o MAC do router: muito mais suspeito do que uma simples mudança.</summary>
    public bool IsStrong => OtherDeviceIp != null;

    public string Key => $"{GatewayIp}|{NewMac}";
}
