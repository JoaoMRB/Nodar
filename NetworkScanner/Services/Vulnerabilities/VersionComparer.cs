using System.Text.RegularExpressions;

namespace NetworkScanner.Services.Vulnerabilities;

/// <summary>
/// Comparação "natural" de versões de software, tolerante aos formatos reais:
/// <c>2.4.58</c>, <c>8.2p1</c> (OpenSSH portátil), <c>1.3.5e</c> (ProFTPD), <c>2022.83</c> (Dropbear),
/// <c>1.0rc1</c> / <c>2.0-beta2</c> (pré-lançamentos).
/// </summary>
/// <remarks>
/// A versão é dividida em blocos numéricos e alfabéticos (separadores <c>. - _ +</c> são ignorados).
/// Blocos numéricos comparam-se como números; alfabéticos sem diferenciar maiúsculas.
/// Quando uma versão é prefixo da outra, o bloco seguinte decide:
/// um marcador de pré-lançamento (alpha, beta, rc, pre, dev…) torna a versão mais longa <em>menor</em>
/// (<c>1.0rc1 &lt; 1.0</c>); qualquer outro sufixo torna-a <em>maior</em> (<c>8.2 &lt; 8.2p1</c>).
/// </remarks>
public static class VersionComparer
{
    private static readonly Regex TokenRegex = new(@"\d+|[A-Za-z]+", RegexOptions.Compiled);

    private static readonly HashSet<string> PreReleaseMarkers = new(StringComparer.OrdinalIgnoreCase)
    {
        "alpha", "a", "beta", "b", "rc", "cr", "pre", "preview", "dev", "snapshot", "m", "milestone"
    };

    // "a"/"b" só contam como pré-lançamento quando seguidos de número (1.0a1, 1.0b2);
    // sozinhos são letras de patch (1.3.5a, 1.3.5b).
    private static readonly HashSet<string> AmbiguousSingleLetters = new(StringComparer.OrdinalIgnoreCase) { "a", "b", "m" };

    public static int Compare(string? left, string? right)
    {
        var a = Tokenize(left);
        var b = Tokenize(right);

        var length = Math.Min(a.Count, b.Count);
        for (var i = 0; i < length; i++)
        {
            var cmp = CompareTokens(a[i], b[i]);
            if (cmp != 0)
                return cmp;
        }

        if (a.Count == b.Count)
            return 0;

        // Uma versão é prefixo da outra: o primeiro bloco extra decide.
        var longer = a.Count > b.Count ? a : b;
        var extraIndex = length;
        var longerIsSmaller = IsPreRelease(longer, extraIndex);
        var sign = a.Count > b.Count ? 1 : -1;
        return longerIsSmaller ? -sign : sign;
    }

    public static bool AreEqual(string? left, string? right) => Compare(left, right) == 0;

    /// <summary>Parte numérica inicial, ex.: <c>8.2p1</c> → <c>8.2</c>; <c>1.3.5e</c> → <c>1.3.5</c>.</summary>
    public static string GetNumericBase(string version)
    {
        var match = Regex.Match(version ?? "", @"^\d+(?:\.\d+)*");
        return match.Success ? match.Value : "";
    }

    private static List<string> Tokenize(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
            return [];
        return TokenRegex.Matches(version).Select(m => m.Value).ToList();
    }

    private static bool IsNumeric(string token) => token.Length > 0 && char.IsDigit(token[0]);

    private static int CompareTokens(string x, string y)
    {
        var xNum = IsNumeric(x);
        var yNum = IsNumeric(y);

        if (xNum && yNum)
        {
            // Comparação numérica sem overflow: remover zeros à esquerda e comparar comprimento.
            var xs = x.TrimStart('0');
            var ys = y.TrimStart('0');
            if (xs.Length != ys.Length)
                return xs.Length.CompareTo(ys.Length);
            return string.CompareOrdinal(xs, ys);
        }

        if (!xNum && !yNum)
        {
            var xPre = PreReleaseMarkers.Contains(x);
            var yPre = PreReleaseMarkers.Contains(y);
            if (xPre != yPre)
                return xPre ? -1 : 1;
            return string.Compare(x, y, StringComparison.OrdinalIgnoreCase);
        }

        // Número vs. texto na mesma posição: o número é considerado maior (ex.: 2.0.1 > 2.0.beta).
        return xNum ? 1 : -1;
    }

    private static bool IsPreRelease(List<string> tokens, int index)
    {
        var token = tokens[index];
        if (IsNumeric(token) || !PreReleaseMarkers.Contains(token))
            return false;

        if (AmbiguousSingleLetters.Contains(token))
            return index + 1 < tokens.Count && IsNumeric(tokens[index + 1]);

        return true;
    }
}
