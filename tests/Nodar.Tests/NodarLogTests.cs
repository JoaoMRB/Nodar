using System.Net;
using System.Net.Sockets;
using Nodar.Core;
using Nodar.Core.Monitoring;
using Nodar.Core.Services;
using Nodar.Core.Settings;

namespace Nodar.Tests;

/// <summary>Falhas "de melhor esforço": o que se engole, o que se regista e o que nunca se perde.</summary>
public sealed class NodarLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nodar-log-tests-" + Guid.NewGuid().ToString("N"));

    public NodarLogTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); }
        catch (IOException) { /* limpeza de uma pasta temporária */ }
    }

    // ---------------------------------------------------------------- Swallow

    [Fact]
    public void Swallow_never_swallows_a_cancellation_requested_by_the_caller()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.False(NodarLog.Swallow(new OperationCanceledException(cts.Token), "teste", cts.Token));
        Assert.False(NodarLog.Swallow(new TaskCanceledException(), "teste", cts.Token));
    }

    [Fact]
    public void Swallow_swallows_timeouts_that_are_not_a_user_cancellation()
    {
        // O timeout interno de uma sonda também é um OperationCanceledException, mas o token do utilizador está vivo.
        Assert.True(NodarLog.Swallow(new OperationCanceledException(), "teste", CancellationToken.None));
        Assert.True(NodarLog.Swallow(new OperationCanceledException(), "teste")); // sem token (tarefa em segundo plano)
    }

    [Theory]
    [MemberData(nameof(ExpectedFailures))]
    public void Expected_failures_are_swallowed_without_being_logged(Exception ex)
    {
        var context = "esperada-" + ex.GetType().Name;
        var logged = Capture(context, () => Assert.True(NodarLog.Swallow(ex, context)));
        Assert.Empty(logged);
    }

    public static TheoryData<Exception> ExpectedFailures() => new()
    {
        new SocketException((int)SocketError.ConnectionRefused),
        new IOException("ficheiro em uso"),
        new FileNotFoundException(),
        new TimeoutException(),
        new HttpRequestException("sem internet"),
        new UnauthorizedAccessException(),
        new System.Text.Json.JsonException("ficheiro corrompido"),
        new ObjectDisposedException("socket"),
        new AggregateException(new SocketException(), new IOException())
    };

    [Fact]
    public void Unexpected_failures_are_swallowed_but_logged_once()
    {
        const string context = "inesperada-bug";
        var logged = Capture(context, () =>
        {
            Assert.True(NodarLog.Swallow(new NullReferenceException("bug"), context));
            Assert.True(NodarLog.Swallow(new NullReferenceException("bug outra vez"), context)); // mesmo sítio e tipo
            Assert.True(NodarLog.Swallow(new InvalidOperationException("outro tipo"), context));
        });

        Assert.Equal(2, logged.Count); // um por tipo: não inunda o registo
        Assert.Contains(logged, e => e is NullReferenceException);
        Assert.Contains(logged, e => e is InvalidOperationException);
    }

    [Fact]
    public void A_failing_sink_never_breaks_the_caller()
    {
        var previous = NodarLog.Sink;
        NodarLog.Sink = (_, _) => throw new IOException("disco cheio");
        try
        {
            Assert.True(NodarLog.Swallow(new NullReferenceException(), "sink-que-falha"));
        }
        finally
        {
            NodarLog.Sink = previous;
        }
    }

    private static List<Exception> Capture(string context, Action act)
    {
        var logged = new List<Exception>();
        var previous = NodarLog.Sink;
        NodarLog.Sink = (ctx, ex) =>
        {
            if (ctx == context)
                lock (logged) logged.Add(ex);
        };
        try { act(); }
        finally { NodarLog.Sink = previous; }
        lock (logged) return [.. logged];
    }

    // ---------------------------------------------------------------- O "Parar" já não é ignorado

    [Fact]
    public async Task Cancelling_during_service_detection_stops_it_instead_of_being_swallowed()
    {
        // Um servidor que aceita a ligação mas nunca diz nada: a leitura do banner fica à espera.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(300); // o utilizador carrega em "Parar" a meio da leitura

        // Antes, o catch genérico da deteção de serviços engolia este cancelamento (com uma só porta, ou na última,
        // nada o voltava a verificar) e devolvia um resultado normal como se nada tivesse acontecido.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ServiceDetectionService.DetectServicesAsync("127.0.0.1", [port], cts.Token));
    }

    // ---------------------------------------------------------------- Ficheiros corrompidos

    [Fact]
    public void A_corrupt_settings_file_falls_back_to_defaults_and_keeps_a_copy()
    {
        var path = Path.Combine(_dir, "settings.json");
        const string content = "{ \"nvdApiKey\": \"a-minha-chave\", }"; // vírgula a mais
        File.WriteAllText(path, content);

        var settings = AppSettings.Load(path);

        Assert.NotNull(settings);
        Assert.Equal(content, File.ReadAllText(path + ".corrupt"));
    }

    [Fact]
    public void Saving_over_a_corrupt_settings_file_does_not_lose_its_content()
    {
        var path = Path.Combine(_dir, "settings.json");
        const string content = "{ \"nvdApiKey\": \"a-minha-chave\" ";
        File.WriteAllText(path, content);

        new AppSettings().Save(path);

        Assert.Equal(content, File.ReadAllText(path + ".corrupt"));
        Assert.Contains("\"language\"", File.ReadAllText(path), StringComparison.OrdinalIgnoreCase); // ficheiro novo, válido
    }

    [Fact]
    public void A_corrupt_history_is_kept_aside_before_the_tracker_starts_empty()
    {
        var historyPath = Path.Combine(_dir, "history.json");
        const string content = "[{ isto não é json";
        File.WriteAllText(historyPath, content);

        var tracker = new DeviceTracker(_dir);
        tracker.Load();

        Assert.Empty(tracker.History);
        Assert.Equal(content, File.ReadAllText(historyPath + ".corrupt"));
    }

    [Fact]
    public void A_missing_or_valid_file_creates_no_backup()
    {
        var tracker = new DeviceTracker(_dir);
        tracker.Load(); // sem ficheiros

        Assert.Empty(Directory.GetFiles(_dir, "*.corrupt"));
    }
}
