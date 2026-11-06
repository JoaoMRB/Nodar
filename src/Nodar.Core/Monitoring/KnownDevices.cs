using Nodar.Core.Models;

namespace Nodar.Core.Monitoring;

/// <summary>
/// Os dispositivos que o utilizador conhece ("é meu"), os que não reconhece e os nomes e notas que lhes deu.
/// </summary>
/// <remarks>
/// <para><b>Privacidade:</b> tudo fica em <c>known-devices.json</c>, na pasta de dados do utilizador. Não há envio
/// para fora, e o ficheiro nunca faz parte do repositório.</para>
/// <para>Enquanto o utilizador não marcar nada, o Nodar comporta-se como sempre (avisa dos dispositivos novos). Só
/// depois de começar a marcar é que "por rever" passa a significar algo, e é aí que os desconhecidos que voltam à
/// rede geram avisos. Assim ninguém é inundado de alertas antes de ter dito quais são os seus dispositivos.</para>
/// </remarks>
public sealed class KnownDevices
{
    public const int MaxNameLength = 60;
    public const int MaxNoteLength = 500;

    private sealed class State
    {
        public bool ReviewActive { get; set; }
        public bool PromptDismissed { get; set; }
        public List<DeviceLabel> Labels { get; set; } = [];
    }

    private readonly string _path;
    private readonly Func<DateTime> _now;
    private readonly Dictionary<string, DeviceLabel> _labels = new(StringComparer.OrdinalIgnoreCase);
    private bool _reviewActive;
    private bool _promptDismissed;

    public KnownDevices(string dataDirectory, Func<DateTime>? clock = null)
    {
        _path = Path.Combine(dataDirectory, "known-devices.json");
        _now = clock ?? (() => DateTime.Now);
    }

    /// <summary>O utilizador já começou a dizer quais são os seus dispositivos.</summary>
    public bool ReviewActive => _reviewActive;

    /// <summary>O utilizador fechou o convite "marcar todos como conhecidos".</summary>
    public bool PromptDismissed => _promptDismissed;

    public IReadOnlyCollection<DeviceLabel> Labels => _labels.Values;

    public void Load()
    {
        _labels.Clear();
        var state = JsonStore.Read<State>(_path) ?? new State();
        _reviewActive = state.ReviewActive;
        _promptDismissed = state.PromptDismissed;
        foreach (var label in state.Labels.Where(l => !string.IsNullOrWhiteSpace(l.Key)))
        {
            label.Name = Clean(label.Name, MaxNameLength);
            label.Note = Clean(label.Note, MaxNoteLength);
            _labels[label.Key] = label;
        }
    }

    public DeviceLabel? Find(string key) => _labels.GetValueOrDefault(key);

    public DeviceTrust TrustOf(string key) => Find(key)?.Trust ?? DeviceTrust.Unreviewed;

    /// <summary>Se o dispositivo merece atenção: suspeito, sempre; por rever, só depois de o utilizador ter começado a marcar.</summary>
    public DeviceAttention Attention(string key) => TrustOf(key) switch
    {
        DeviceTrust.Suspicious => DeviceAttention.Suspicious,
        DeviceTrust.Unreviewed when _reviewActive => DeviceAttention.Unknown,
        _ => DeviceAttention.None
    };

    public void SetTrust(string key, DeviceTrust trust)
    {
        if (string.IsNullOrWhiteSpace(key))
            return;
        var label = GetOrCreate(key);
        label.Trust = trust;
        label.UpdatedAt = _now();
        if (trust != DeviceTrust.Unreviewed)
            _reviewActive = true; // marcar um dispositivo é começar a rever a rede
        Tidy(label);
        Save();
    }

    /// <summary>Guarda o nome e a nota (limpos e com tamanho limitado). Devolve o que ficou guardado.</summary>
    public (string Name, string Note) SetDetails(string key, string? name, string? note)
    {
        if (string.IsNullOrWhiteSpace(key))
            return ("", "");
        var label = GetOrCreate(key);
        label.Name = Clean(name, MaxNameLength);
        label.Note = Clean(note, MaxNoteLength);
        label.UpdatedAt = _now();
        var kept = (label.Name, label.Note);
        Tidy(label);
        Save();
        return kept;
    }

    /// <summary>
    /// Marca como conhecidos os dispositivos dados, exceto os que o utilizador já marcou como suspeitos (essa
    /// decisão é deliberada e não se desfaz em bloco). Devolve quantos passaram a conhecidos.
    /// </summary>
    public int MarkAllKnown(IEnumerable<string> keys)
    {
        var changed = 0;
        foreach (var key in keys.Where(k => !string.IsNullOrWhiteSpace(k)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var label = GetOrCreate(key);
            if (label.Trust != DeviceTrust.Unreviewed)
                continue;
            label.Trust = DeviceTrust.Known;
            label.UpdatedAt = _now();
            changed++;
        }
        _reviewActive = true;
        Save();
        return changed;
    }

    public void DismissPrompt()
    {
        _promptDismissed = true;
        Save();
    }

    // ---------------------------------------------------------------- interno

    private DeviceLabel GetOrCreate(string key)
    {
        if (!_labels.TryGetValue(key, out var label))
            _labels[key] = label = new DeviceLabel { Key = key.Trim(), UpdatedAt = _now() };
        return label;
    }

    /// <summary>Um dispositivo "por rever", sem nome nem nota, não precisa de entrada no ficheiro.</summary>
    private void Tidy(DeviceLabel label)
    {
        if (label.Trust == DeviceTrust.Unreviewed && label.Name.Length == 0 && label.Note.Length == 0)
            _labels.Remove(label.Key);
    }

    /// <summary>Sem caracteres de controlo (exceto quebras de linha nas notas) e com tamanho limitado.</summary>
    private static string Clean(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var kept = new string(value.Where(c => !char.IsControl(c) || c is '\n' or '\r').ToArray()).Trim();
        if (max == MaxNameLength)
            kept = kept.Replace("\r", " ").Replace("\n", " ");
        return kept.Length > max ? kept[..max].TrimEnd() : kept;
    }

    private void Save() =>
        JsonStore.Write(_path, new State
        {
            ReviewActive = _reviewActive,
            PromptDismissed = _promptDismissed,
            Labels = [.. _labels.Values.OrderBy(l => l.Key, StringComparer.OrdinalIgnoreCase)]
        });
}
