using Nodar.Core.Models;

namespace Nodar.Core.Monitoring;

/// <summary>
/// Lembra os redirecionamentos de porta (UPnP) já vistos, para avisar quando aparece um novo e para dizer desde
/// quando existe cada um (o router não guarda essa data).
/// </summary>
/// <remarks>
/// O primeiro scan com leitura bem-sucedida é a linha de base: o que já lá estava não é "novo". Um redirecionamento
/// só é esquecido depois de falhar <see cref="MissedBeforeForgotten"/> leituras seguidas: uma resposta vazia
/// passageira do router não pode fazer o mesmo redirecionamento parecer novo no scan seguinte.
/// </remarks>
public sealed class PortMappingTracker
{
    public const int MissedBeforeForgotten = 3;

    public sealed class Record
    {
        public DateTime FirstSeenAt { get; set; }
        public int Missed { get; set; }
    }

    public sealed class State
    {
        public bool Baselined { get; set; }
        public Dictionary<string, Record> Mappings { get; set; } = new(StringComparer.Ordinal);
    }

    private readonly string _path;
    private readonly Func<DateTime> _now;
    private State _state = new();

    public PortMappingTracker(string dataDirectory, Func<DateTime>? clock = null)
    {
        _path = Path.Combine(dataDirectory, "upnp-mappings.json");
        _now = clock ?? (() => DateTime.Now);
    }

    public void Load() => _state = JsonStore.Read<State>(_path) ?? new State();

    /// <summary>Quando o Nodar viu pela primeira vez este redirecionamento (<c>null</c> se nunca o viu).</summary>
    public DateTime? FirstSeen(PortMapping mapping) =>
        _state.Mappings.TryGetValue(mapping.Key, out var record) ? record.FirstSeenAt : null;

    /// <summary>Aplica uma leitura do router e devolve os redirecionamentos ativos que nunca tinham sido vistos.</summary>
    public IReadOnlyList<PortMapping> Apply(UpnpReport report)
    {
        if (report.Status != UpnpStatus.Ok)
            return []; // sem leitura não se sabe nada: não se esquece nem se anuncia nada

        var now = _now();
        var isBaseline = !_state.Baselined;
        var added = new List<PortMapping>();
        var current = new HashSet<string>(StringComparer.Ordinal);

        foreach (var mapping in report.Mappings)
        {
            if (!current.Add(mapping.Key))
                continue; // o router repetiu a entrada
            if (_state.Mappings.TryGetValue(mapping.Key, out var record))
            {
                record.Missed = 0;
                continue;
            }
            _state.Mappings[mapping.Key] = new Record { FirstSeenAt = now };
            if (!isBaseline && mapping.Enabled)
                added.Add(mapping);
        }

        // Uma lista cortada ao limite não diz o que falta: só se esquece com a lista completa.
        if (!report.Truncated)
        {
            foreach (var key in _state.Mappings.Keys.Where(k => !current.Contains(k)).ToList())
            {
                if (++_state.Mappings[key].Missed >= MissedBeforeForgotten)
                    _state.Mappings.Remove(key);
            }
        }

        _state.Baselined = true;
        JsonStore.Write(_path, _state);
        return added;
    }
}
