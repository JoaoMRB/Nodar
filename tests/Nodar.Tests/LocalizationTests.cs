using System.Text.RegularExpressions;
using Nodar.Core.Localization;

namespace Nodar.Tests;

[CollectionDefinition("Loc", DisableParallelization = true)]
public class LocCollection;

[Collection("Loc")] // mudam o idioma global: correm isolados, sem paralelismo com os outros testes
public class LocalizationTests
{
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Nodar.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Nodar.sln não encontrado");
    }

    [Fact]
    public void Portuguese_and_English_have_the_same_keys()
    {
        var pt = Loc.Instance.KeysOf("pt").ToHashSet();
        var en = Loc.Instance.KeysOf("en").ToHashSet();
        Assert.True(pt.Count > 200);
        Assert.Empty(pt.Except(en));
        Assert.Empty(en.Except(pt));
    }

    [Fact]
    public void Placeholders_match_between_languages()
    {
        var previous = Loc.Instance.Language;
        try
        {
            var mismatches = new List<string>();
            foreach (var key in Loc.Instance.KeysOf("pt"))
            {
                Loc.Instance.Language = "pt";
                var pt = Placeholders(Loc.Instance[key]);
                Loc.Instance.Language = "en";
                var en = Placeholders(Loc.Instance[key]);
                if (!pt.SetEquals(en))
                    mismatches.Add(key);
            }
            Assert.Empty(mismatches);
        }
        finally
        {
            Loc.Instance.Language = previous;
        }

        static HashSet<string> Placeholders(string text) =>
            Regex.Matches(text, @"\{\d+\}").Select(m => m.Value).ToHashSet();
    }

    [Fact]
    public void Every_key_used_in_code_and_xaml_exists()
    {
        var src = Path.Combine(RepoRoot(), "src");
        var used = new HashSet<string>();
        foreach (var file in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories).Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")))
            foreach (Match m in Regex.Matches(File.ReadAllText(file), @"\b(?:T|F|Plural)\(""(?<k>[A-Za-z0-9_.]+)"""))
                used.Add(m.Groups["k"].Value);
        foreach (var file in Directory.EnumerateFiles(src, "*.axaml", SearchOption.AllDirectories))
            foreach (Match m in Regex.Matches(File.ReadAllText(file), @"\{l:T (?<k>[A-Za-z0-9_.]+)\}"))
                used.Add(m.Groups["k"].Value);

        used.Remove("severity."); // prefixo dinâmico (severity.Critical, …)
        Assert.True(used.Count > 200);
        var missing = used.Where(k => !Loc.Instance.Has(k)).ToList();
        Assert.Empty(missing);
    }

    [Fact]
    public void No_hardcoded_portuguese_left_in_xaml()
    {
        var xaml = File.ReadAllText(Path.Combine(RepoRoot(), "src", "Nodar.App", "Views", "MainWindow.axaml"));
        var literals = Regex.Matches(xaml, @"(?:Text|Watermark|ToolTip\.Tip|Header)=""(?<v>[^""{]*[A-Za-zÀ-ú][^""]*)""")
            .Select(m => m.Groups["v"].Value.Trim())
            .Where(v => v is not ("Nodar" or "MAC" or "Hostname" or "CVSS" or "KEV"))
            .ToList();
        Assert.Empty(literals);
    }

    [Fact]
    public void Device_types_stored_in_portuguese_are_translated_for_display()
    {
        var previous = Loc.Instance.Language;
        try
        {
            Loc.Instance.Language = "en";
            Assert.Equal("Phone", Loc.DeviceType("Telemóvel"));
            Assert.Equal("Smart home", Loc.DeviceType("Smart Home"));
            Assert.Equal("Printer", Loc.DeviceType("Impressora"));
            Assert.Equal("Algo novo", Loc.DeviceType("Algo novo")); // desconhecido: mantém-se
            Loc.Instance.Language = "pt";
            Assert.Equal("Telemóvel", Loc.DeviceType("Telemóvel"));
        }
        finally
        {
            Loc.Instance.Language = previous;
        }
    }

    [Fact]
    public void Plural_and_format()
    {
        var previous = Loc.Instance.Language;
        try
        {
            Loc.Instance.Language = "en";
            Assert.Equal("1 port", Loc.Plural("badge.ports", 1));
            Assert.Equal("3 ports", Loc.Plural("badge.ports", 3));
            Assert.Equal("nginx 1.18.0 · port 80", Loc.F("vuln.where", "nginx", "1.18.0", 80));
            Loc.Instance.Language = "pt";
            Assert.Equal("1 porta", Loc.Plural("badge.ports", 1));
            Assert.Equal("3 portas", Loc.Plural("badge.ports", 3));
        }
        finally
        {
            Loc.Instance.Language = previous;
        }
    }

    [Fact]
    public void Changing_language_notifies_bindings()
    {
        var previous = Loc.Instance.Language;
        var raised = new List<string?>();
        void Handler(object? s, System.ComponentModel.PropertyChangedEventArgs e) => raised.Add(e.PropertyName);
        Loc.Instance.PropertyChanged += Handler;
        try
        {
            Loc.Instance.Language = previous == "pt" ? "en" : "pt";
            Assert.Contains("Item[]", raised); // convenção WPF
            Assert.Contains("Item", raised);   // a que o Avalonia usa para indexadores (sem ela a interface não muda de idioma)
        }
        finally
        {
            Loc.Instance.PropertyChanged -= Handler;
            Loc.Instance.Language = previous;
        }
    }

    [Fact]
    public void Unknown_keys_fall_back_to_the_key() =>
        Assert.Equal("nao.existe", Loc.T("nao.existe"));
}
