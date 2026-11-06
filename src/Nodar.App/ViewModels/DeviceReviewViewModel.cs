using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Nodar.Core.Models;
using Nodar.Core.Monitoring;
using static Nodar.Core.Localization.Loc;

namespace Nodar.App.ViewModels;

/// <summary>
/// Dizer quais são os dispositivos da rede: "é meu", "não reconheço", nome e nota. Gere também o convite de
/// primeira utilização ("marcar todos como conhecidos") e as contagens de quantos ficam por rever.
/// </summary>
/// <remarks>
/// Os dados vão para <see cref="KnownDevices"/>, que os guarda só neste PC (<c>known-devices.json</c>).
/// </remarks>
public sealed partial class DeviceReviewViewModel(KnownDevices store) : ObservableObject
{
    private IReadOnlyList<DeviceItemViewModel> _devices = [];
    private IReadOnlyCollection<string> _extraKeys = [];

    /// <summary>Os rótulos mudaram: a lista de dispositivos tem de ser refeita.</summary>
    public event Action? Changed;

    /// <summary>"Marcar todos como conhecidos" foi usado (com o número de dispositivos marcados).</summary>
    public event Action<int>? AllMarkedKnown;

    // ================================================================ Visão geral

    /// <summary>O utilizador já começou a marcar os seus dispositivos (e por isso "por rever" passa a contar).</summary>
    [ObservableProperty] private bool _isActive;

    [ObservableProperty] private bool _showPrompt;
    [ObservableProperty] private string _promptText = "";
    [ObservableProperty] private int _unreviewedCount;
    [ObservableProperty] private int _suspiciousCount;

    /// <param name="devices">Os dispositivos da lista (online e, se mostrados, offline).</param>
    /// <param name="hasScanned">Já houve um scan.</param>
    /// <param name="historyKeys">Chaves de todos os dispositivos já vistos (inclui os que a lista não mostra).</param>
    public void Refresh(IReadOnlyList<DeviceItemViewModel> devices, bool hasScanned, IReadOnlyCollection<string> historyKeys)
    {
        _devices = devices;
        _extraKeys = historyKeys;

        IsActive = store.ReviewActive;
        UnreviewedCount = devices.Count(d => d.Attention == DeviceAttention.Unknown);
        SuspiciousCount = devices.Count(d => d.Attention == DeviceAttention.Suspicious);

        // O convite só aparece enquanto o utilizador ainda não marcou nada nem o dispensou.
        var online = devices.Count(d => d.IsOnline);
        ShowPrompt = hasScanned && !store.ReviewActive && !store.PromptDismissed && online > 0;
        PromptText = Plural("review.prompt", online);
    }

    [RelayCommand]
    private void MarkAllKnown()
    {
        var keys = _devices.Select(d => d.Key).Concat(_extraKeys);
        var changed = store.MarkAllKnown(keys);
        Changed?.Invoke();
        AllMarkedKnown?.Invoke(changed);
    }

    [RelayCommand]
    private void DismissPrompt()
    {
        store.DismissPrompt();
        ShowPrompt = false;
    }

    // ================================================================ O dispositivo aberto no painel

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasDevice), nameof(IsKnown), nameof(IsUnreviewed), nameof(IsSuspicious), nameof(IsDirty))]
    private DeviceItemViewModel? _device;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDirty))]
    private string _editName = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDirty))]
    private string _editNote = "";

    public bool HasDevice => Device != null;
    public bool IsKnown => Device?.Trust == DeviceTrust.Known;
    public bool IsUnreviewed => Device?.Trust == DeviceTrust.Unreviewed;
    public bool IsSuspicious => Device?.Trust == DeviceTrust.Suspicious;

    /// <summary>Há um nome ou uma nota por guardar.</summary>
    public bool IsDirty => Device != null && (EditName.Trim() != Device.CustomName || EditNote.Trim() != Device.Note);

    /// <summary>
    /// O painel passou a mostrar outro dispositivo. Se for o mesmo (a lista foi refeita depois de mudar o estado) e
    /// houver texto por guardar, esse texto não se perde.
    /// </summary>
    public void Select(DeviceItemViewModel? device)
    {
        // Ao refazer a lista (por exemplo depois de mudar o estado) a seleção passa por "nenhum" por um instante e
        // volta ao mesmo dispositivo: o texto por guardar tem de sobreviver a essa passagem.
        var wasDirty = IsDirty;
        var previousKey = Device?.Key ?? _leftKey;
        var keepEdits = device != null && device.Key == previousKey && (wasDirty || _leftDirty);

        if (device == null)
        {
            _leftKey = Device?.Key ?? _leftKey;
            _leftDirty = wasDirty || _leftDirty;
            Device = null;
            if (!_leftDirty)
            {
                EditName = "";
                EditNote = "";
            }
            return;
        }

        Device = device;
        _leftKey = null;
        _leftDirty = false;
        if (keepEdits)
            return;
        EditName = device.CustomName;
        EditNote = device.Note;
    }

    private string? _leftKey;
    private bool _leftDirty;

    /// <param name="state">"known", "suspicious" ou "unreviewed".</param>
    [RelayCommand]
    private void SetTrust(string? state)
    {
        if (Device == null)
            return;
        var trust = state switch
        {
            "known" => DeviceTrust.Known,
            "suspicious" => DeviceTrust.Suspicious,
            _ => DeviceTrust.Unreviewed
        };
        store.SetTrust(Device.Key, trust);
        Changed?.Invoke();
    }

    [RelayCommand]
    private void SaveDetails()
    {
        if (Device == null)
            return;
        var (name, note) = store.SetDetails(Device.Key, EditName, EditNote);
        EditName = name;
        EditNote = note;
        Changed?.Invoke();
    }
}
