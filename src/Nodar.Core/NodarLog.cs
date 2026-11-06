using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security;
using System.Security.Authentication;
using System.Text.Json;

namespace Nodar.Core;

/// <summary>
/// Tratamento das falhas "de melhor esforço" (sondas de rede, ficheiros opcionais, registo do Windows).
/// <para>
/// Um dispositivo que não responde, uma ligação recusada ou um ficheiro bloqueado não são erros: o scan segue.
/// Mas um <c>catch {}</c> também esconderia bugs a sério e engoliria o cancelamento pedido pelo utilizador.
/// Em vez disso usa-se como filtro de exceção:
/// <code>catch (Exception ex) when (NodarLog.Swallow(ex, "contexto", ct)) { /* valor por omissão */ }</code>
/// </para>
/// </summary>
public static class NodarLog
{
    private static readonly ConcurrentDictionary<string, byte> Reported = new();

    /// <summary>Para onde vão os erros inesperados (a app liga isto ao seu registo em ficheiro).</summary>
    public static Action<string, Exception>? Sink { get; set; }

    /// <summary>
    /// Falhas normais de rede, ficheiros e sistema: acontecem no dia a dia e não indicam um bug.
    /// </summary>
    public static bool IsExpected(Exception ex) => ex switch
    {
        SocketException or IOException or TimeoutException or HttpRequestException or PingException => true,
        OperationCanceledException or ObjectDisposedException => true, // timeouts e ligações fechadas durante o cancelamento
        AuthenticationException => true,                               // TLS recusado ou com certificado estranho
        UnauthorizedAccessException or SecurityException or Win32Exception => true,
        JsonException => true,                                         // ficheiro de dados corrompido
        AggregateException aggregate => aggregate.InnerExceptions.All(IsExpected),
        _ => false
    };

    /// <summary>
    /// Para usar em <c>catch (Exception ex) when (...)</c>. Devolve <c>false</c> (a exceção segue o seu caminho)
    /// se o utilizador cancelou; caso contrário devolve <c>true</c> (engolir), registando só as inesperadas.
    /// </summary>
    public static bool Swallow(Exception ex, string context, CancellationToken ct = default)
    {
        if (ex is OperationCanceledException && ct.IsCancellationRequested)
            return false;
        if (!IsExpected(ex))
            Unexpected(context, ex);
        return true;
    }

    /// <summary>
    /// Um ficheiro de dados está corrompido e vai ser ignorado (a app começa com valores por omissão). Como a
    /// gravação seguinte o substituiria, guarda antes uma cópia em <c>&lt;ficheiro&gt;.corrupt</c>, para o
    /// utilizador não perder o conteúdo (histórico, chave da NVD…) por causa de uma vírgula a mais.
    /// </summary>
    public static void CorruptFile(string path, Exception ex)
    {
        Unexpected($"Ficheiro corrompido: {Path.GetFileName(path)}", ex);
        try
        {
            File.Copy(path, path + ".corrupt", overwrite: true);
        }
        catch (Exception copyError) when (Swallow(copyError, "Guardar cópia do ficheiro corrompido"))
        {
            // Sem cópia (disco cheio, sem permissões): já ficou registado acima.
        }
    }

    /// <summary>Regista uma falha inesperada (no máximo uma vez por contexto e tipo, para não inundar o registo).</summary>
    public static void Unexpected(string context, Exception ex)
    {
        if (!Reported.TryAdd($"{context}|{ex.GetType().FullName}", 0))
            return;

        Debug.WriteLine($"[Nodar] {context}: {ex}");
        try
        {
            Sink?.Invoke(context, ex);
        }
        catch (Exception sinkError)
        {
            // O registo nunca pode falhar o chamador (corre dentro de filtros de exceção).
            Debug.WriteLine($"[Nodar] O registo falhou: {sinkError.Message}");
        }
    }
}
