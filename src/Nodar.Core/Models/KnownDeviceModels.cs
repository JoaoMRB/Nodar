using System.Text.Json.Serialization;

namespace Nodar.Core.Models;

/// <summary>O que o utilizador decidiu sobre um dispositivo.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum DeviceTrust
{
    /// <summary>Ainda não foi visto pelo utilizador (o estado de todos os dispositivos novos).</summary>
    Unreviewed,

    /// <summary>"É meu" (ou de alguém que o utilizador conhece).</summary>
    Known,

    /// <summary>"Não reconheço": o utilizador quer ser avisado sempre que apareça.</summary>
    Suspicious
}

/// <summary>Quanta atenção um dispositivo merece neste momento.</summary>
public enum DeviceAttention
{
    None,

    /// <summary>Por rever, depois de o utilizador ter começado a marcar os seus dispositivos.</summary>
    Unknown,

    Suspicious
}

/// <summary>
/// O estado, o nome e a nota que o utilizador deu a um dispositivo.
/// São dados pessoais: ficam só em <c>%LOCALAPPDATA%\Nodar\known-devices.json</c>, nunca saem do computador e
/// nunca entram no repositório.
/// </summary>
public sealed class DeviceLabel
{
    /// <summary>Identidade do dispositivo (a do <c>DeviceTracker</c>: MAC, MAC@IP ou IP).</summary>
    public string Key { get; set; } = "";

    public DeviceTrust Trust { get; set; }

    /// <summary>Nome escolhido pelo utilizador (vazio = usar o nome automático).</summary>
    public string Name { get; set; } = "";

    public string Note { get; set; } = "";
    public DateTime UpdatedAt { get; set; } = DateTime.Now;
}
