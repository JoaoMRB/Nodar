using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace NetworkScanner.Services.Vulnerabilities;

/// <summary>
/// Cliente mínimo da NVD CVE API 2.0 (https://nvd.nist.gov/developers/vulnerabilities).
/// </summary>
/// <remarks>
/// <para>Privacidade: só é enviado o identificador do produto (ex.: <c>cpe:2.3:a:openbsd:openssh</c>).
/// Nunca são enviados IPs, MACs, hostnames nem a versão detetada; a comparação de versões é feita localmente.</para>
/// <para>Limites da NVD: 5 pedidos por 30 s sem chave, 50 com chave. A chave (gratuita) pode ser definida na
/// variável de ambiente <c>NVD_API_KEY</c> ou em <c>%LOCALAPPDATA%\Nodar\settings.json</c> (<c>"nvdApiKey"</c>).</para>
/// </remarks>
public sealed class NvdClient
{
    private const string BaseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private const int PageSize = 2000; // máximo permitido pela API

    private static readonly HttpClient Http = CreateHttpClient();
    private static readonly SemaphoreSlim RateGate = new(1, 1);
    private static DateTime _lastRequestUtc = DateTime.MinValue;

    private readonly string? _apiKey;

    public NvdClient(string? apiKey)
    {
        _apiKey = string.IsNullOrWhiteSpace(apiKey) ? null : apiKey.Trim();
    }

    public bool HasApiKey => _apiKey != null;

    private TimeSpan MinInterval => HasApiKey ? TimeSpan.FromMilliseconds(700) : TimeSpan.FromSeconds(6.5);

    /// <summary>Descarrega todos os CVEs com regras para <c>vendor:product</c>, percorrendo todas as páginas.</summary>
    public async Task<List<CveRecord>> GetProductCvesAsync(string vendor, string product, CancellationToken ct)
    {
        var all = new List<CveRecord>();
        var startIndex = 0;

        while (true)
        {
            var url = $"{BaseUrl}?virtualMatchString=cpe:2.3:a:{Uri.EscapeDataString(vendor)}:{Uri.EscapeDataString(product)}" +
                      $"&noRejected&resultsPerPage={PageSize}&startIndex={startIndex}";

            using var document = await GetJsonWithRetryAsync(url, ct);
            var page = NvdParser.ParsePage(document, vendor, product);
            all.AddRange(page.Records);

            var received = page.ResultsPerPage > 0 ? page.ResultsPerPage : PageSize;
            startIndex += received;
            if (startIndex >= page.TotalResults || received == 0)
                break;
        }

        return all;
    }

    private async Task<JsonDocument> GetJsonWithRetryAsync(string url, CancellationToken ct)
    {
        var delays = new[] { TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(35) };

        for (var attempt = 0; ; attempt++)
        {
            await WaitForRateLimitAsync(ct);

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (_apiKey != null)
                request.Headers.Add("apiKey", _apiKey);

            HttpResponseMessage? response = null;
            try
            {
                response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

                if (response.IsSuccessStatusCode)
                {
                    await using var stream = await response.Content.ReadAsStreamAsync(ct);
                    return await JsonDocument.ParseAsync(stream, cancellationToken: ct);
                }

                // A NVD responde 403 quando o limite de pedidos é excedido; 429/5xx também são temporários.
                var transient = response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests
                                || (int)response.StatusCode >= 500;
                if (!transient || attempt >= delays.Length)
                    throw new HttpRequestException($"NVD respondeu {(int)response.StatusCode} {response.ReasonPhrase}", null, response.StatusCode);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested && attempt < delays.Length)
            {
                // timeout: tentar de novo
            }
            catch (HttpRequestException) when (response == null && attempt < delays.Length)
            {
                // falha de ligação: tentar de novo
            }
            finally
            {
                response?.Dispose();
            }

            await Task.Delay(delays[attempt], ct);
        }
    }

    private async Task WaitForRateLimitAsync(CancellationToken ct)
    {
        await RateGate.WaitAsync(ct);
        try
        {
            var wait = _lastRequestUtc + MinInterval - DateTime.UtcNow;
            if (wait > TimeSpan.Zero)
                await Task.Delay(wait, ct);
            _lastRequestUtc = DateTime.UtcNow;
        }
        finally
        {
            RateGate.Release();
        }
    }

    internal static HttpClient CreateHttpClient()
    {
        var client = new HttpClient(new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        })
        {
            Timeout = TimeSpan.FromSeconds(90)
        };
        var version = typeof(NvdClient).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Nodar", version));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }
}
