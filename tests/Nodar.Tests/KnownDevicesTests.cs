using Nodar.Core.Models;
using Nodar.Core.Monitoring;

namespace Nodar.Tests;

/// <summary>Dispositivos conhecidos, suspeitos, nomes e notas. Só dados inventados, em pastas temporárias.</summary>
public sealed class KnownDevicesTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-known-" + Guid.NewGuid().ToString("N"));
    private DateTime _now = new(2026, 11, 6, 10, 0, 0);

    public KnownDevicesTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* limpeza de uma pasta temporária */ }
    }

    private KnownDevices Create()
    {
        var k = new KnownDevices(_dir, () => _now);
        k.Load();
        return k;
    }

    private const string PhoneKey = "AA:BB:CC:00:00:01";
    private const string TvKey = "AA:BB:CC:00:00:02";
    private const string StrangerKey = "AA:BB:CC:00:00:03";

    // ---------------------------------------------------------------- Estado e atenção

    [Fact]
    public void Everything_is_unreviewed_and_asks_for_no_attention_until_the_user_starts_marking()
    {
        var k = Create();

        Assert.False(k.ReviewActive);
        Assert.Equal(DeviceTrust.Unreviewed, k.TrustOf(PhoneKey));
        Assert.Equal(DeviceAttention.None, k.Attention(PhoneKey)); // sem alertas antes de o utilizador dizer quais são os seus
    }

    [Fact]
    public void Marking_one_device_starts_the_review_and_the_others_become_unknown()
    {
        var k = Create();
        k.SetTrust(PhoneKey, DeviceTrust.Known);

        Assert.True(k.ReviewActive);
        Assert.Equal(DeviceAttention.None, k.Attention(PhoneKey));
        Assert.Equal(DeviceAttention.Unknown, k.Attention(StrangerKey));
    }

    [Fact]
    public void A_suspicious_device_always_asks_for_attention_even_before_any_review()
    {
        var k = Create();
        k.SetTrust(StrangerKey, DeviceTrust.Suspicious);

        Assert.Equal(DeviceAttention.Suspicious, k.Attention(StrangerKey));
        Assert.Equal(DeviceAttention.Unknown, k.Attention(TvKey)); // marcar um suspeito também inicia a revisão
    }

    [Fact]
    public void Going_back_to_unreviewed_removes_the_entry_but_keeps_the_review_active()
    {
        var k = Create();
        k.SetTrust(PhoneKey, DeviceTrust.Known);
        k.SetTrust(PhoneKey, DeviceTrust.Unreviewed);

        Assert.Null(k.Find(PhoneKey));
        Assert.True(k.ReviewActive);
        Assert.Equal(DeviceAttention.Unknown, k.Attention(PhoneKey));
    }

    [Fact]
    public void Keys_are_case_insensitive()
    {
        var k = Create();
        k.SetTrust("aa:bb:cc:00:00:01", DeviceTrust.Known);
        Assert.Equal(DeviceTrust.Known, k.TrustOf("AA:BB:CC:00:00:01"));
    }

    [Fact]
    public void Blank_keys_are_ignored()
    {
        var k = Create();
        k.SetTrust("  ", DeviceTrust.Known);
        k.SetDetails("", "nome", "nota");
        Assert.Empty(k.Labels);
        Assert.False(k.ReviewActive);
    }

    // ---------------------------------------------------------------- Marcar todos

    [Fact]
    public void Marking_all_as_known_skips_what_the_user_flagged_as_suspicious()
    {
        var k = Create();
        k.SetTrust(StrangerKey, DeviceTrust.Suspicious);

        var changed = k.MarkAllKnown([PhoneKey, TvKey, StrangerKey, PhoneKey]); // repetidos contam uma vez

        Assert.Equal(2, changed);
        Assert.Equal(DeviceTrust.Known, k.TrustOf(PhoneKey));
        Assert.Equal(DeviceTrust.Known, k.TrustOf(TvKey));
        Assert.Equal(DeviceTrust.Suspicious, k.TrustOf(StrangerKey)); // a decisão deliberada fica
        Assert.True(k.ReviewActive);
    }

    [Fact]
    public void Marking_all_again_counts_only_what_changed()
    {
        var k = Create();
        k.MarkAllKnown([PhoneKey, TvKey]);
        Assert.Equal(1, k.MarkAllKnown([PhoneKey, TvKey, StrangerKey]));
    }

    [Fact]
    public void Dismissing_the_prompt_is_remembered()
    {
        var k = Create();
        Assert.False(k.PromptDismissed);
        k.DismissPrompt();
        Assert.True(Create().PromptDismissed);
    }

    // ---------------------------------------------------------------- Nome e nota

    [Fact]
    public void Name_and_note_are_cleaned_and_limited()
    {
        var k = Create();
        var (name, note) = k.SetDetails(PhoneKey,
            "  Telemóvel\u0007 de teste\n" + new string('x', 200),
            "linha 1\nlinha 2\u0000" + new string('y', 1000));

        Assert.True(name.Length <= KnownDevices.MaxNameLength);
        Assert.StartsWith("Telemóvel de teste x", name);
        Assert.DoesNotContain(name, c => char.IsControl(c));   // sem controlo nem quebras de linha no nome
        Assert.True(note.Length <= KnownDevices.MaxNoteLength);
        Assert.StartsWith("linha 1\nlinha 2y", note);           // a nota mantém as quebras de linha
        Assert.DoesNotContain('\0', note);
    }

    [Fact]
    public void A_name_alone_creates_an_entry_that_stays_unreviewed_and_does_not_start_the_review()
    {
        var k = Create();
        k.SetDetails(PhoneKey, "Telemóvel de teste", "");

        Assert.Equal("Telemóvel de teste", k.Find(PhoneKey)!.Name);
        Assert.Equal(DeviceTrust.Unreviewed, k.TrustOf(PhoneKey));
        Assert.False(k.ReviewActive); // dar um nome não é rever a rede
    }

    [Fact]
    public void Clearing_name_and_note_of_an_unreviewed_device_removes_the_entry()
    {
        var k = Create();
        k.SetDetails(PhoneKey, "Nome", "Nota");
        k.SetDetails(PhoneKey, "  ", null);
        Assert.Null(k.Find(PhoneKey));
    }

    [Fact]
    public void Clearing_name_and_note_of_a_known_device_keeps_the_entry()
    {
        var k = Create();
        k.SetTrust(PhoneKey, DeviceTrust.Known);
        k.SetDetails(PhoneKey, "Nome", "Nota");
        k.SetDetails(PhoneKey, "", "");

        Assert.Equal(DeviceTrust.Known, k.TrustOf(PhoneKey));
    }

    // ---------------------------------------------------------------- Ficheiro

    [Fact]
    public void Everything_survives_a_restart()
    {
        var k = Create();
        k.SetTrust(PhoneKey, DeviceTrust.Known);
        k.SetDetails(PhoneKey, "Telemóvel de teste", "Nota de teste");
        k.SetTrust(StrangerKey, DeviceTrust.Suspicious);

        var again = Create();
        var phone = again.Find(PhoneKey)!;
        Assert.Equal((DeviceTrust.Known, "Telemóvel de teste", "Nota de teste"), (phone.Trust, phone.Name, phone.Note));
        Assert.Equal(DeviceTrust.Suspicious, again.TrustOf(StrangerKey));
        Assert.True(again.ReviewActive);
        Assert.Equal(_now, phone.UpdatedAt);
    }

    [Fact]
    public void The_data_lives_only_in_the_given_folder()
    {
        var k = Create();
        k.SetTrust(PhoneKey, DeviceTrust.Known);

        Assert.Equal([Path.Combine(_dir, "known-devices.json")], Directory.GetFiles(_dir));
    }

    [Fact]
    public void The_trust_is_written_as_text_so_the_file_can_be_read_and_edited()
    {
        Create().SetTrust(PhoneKey, DeviceTrust.Suspicious);
        Assert.Contains("\"Suspicious\"", File.ReadAllText(Path.Combine(_dir, "known-devices.json")));
    }

    [Fact]
    public void A_corrupt_file_starts_empty_and_keeps_a_copy()
    {
        var path = Path.Combine(_dir, "known-devices.json");
        File.WriteAllText(path, "{ não é json");

        var k = Create();

        Assert.Empty(k.Labels);
        Assert.False(k.ReviewActive);
        Assert.Equal("{ não é json", File.ReadAllText(path + ".corrupt")); // o que o utilizador escreveu não se perde
    }

    [Fact]
    public void Hand_edited_values_in_the_file_are_cleaned_when_loaded()
    {
        File.WriteAllText(Path.Combine(_dir, "known-devices.json"),
            "{\"ReviewActive\":true,\"Labels\":[{\"Key\":\"" + PhoneKey + "\",\"Trust\":\"Known\",\"Name\":\"" + new string('n', 300) + "\\u0007\",\"Note\":\"\"},{\"Key\":\"\",\"Trust\":\"Known\"}]}");

        var k = Create();

        Assert.Equal(KnownDevices.MaxNameLength, k.Find(PhoneKey)!.Name.Length);
        Assert.Single(k.Labels); // a entrada sem chave é ignorada
    }

    // ---------------------------------------------------------------- Dispositivos que voltam

    [Fact]
    public void A_device_that_comes_back_is_reported_as_returned_and_a_new_one_is_not()
    {
        var tracker = new DeviceTracker(_dir, () => _now);
        tracker.Load();
        var phone = new DeviceInfo { IpAddress = "192.168.1.20", MacAddress = PhoneKey };
        var tv = new DeviceInfo { IpAddress = "192.168.1.30", MacAddress = TvKey };

        tracker.ApplyScan([phone, tv]);                              // linha de base
        tracker.ApplyScan([tv]);
        tracker.ApplyScan([tv]);                                     // 2 falhas seguidas: o telemóvel saiu
        var back = tracker.ApplyScan([phone, tv]);

        Assert.Equal(PhoneKey, Assert.Single(back.Returned).MacAddress);
        Assert.Empty(back.NewDevices);

        var stranger = new DeviceInfo { IpAddress = "192.168.1.40", MacAddress = StrangerKey };
        var next = tracker.ApplyScan([phone, tv, stranger]);
        Assert.Empty(next.Returned);                                 // um dispositivo novo não é um regresso
        Assert.Single(next.NewDevices);
    }
}
