using System.Text.RegularExpressions;

namespace NetworkScanner.Services.Vulnerabilities;

/// <summary>
/// Extrai produto e versão a partir de banners de serviço (SSH, HTTP, FTP, SMTP, MySQL, Redis).
/// </summary>
/// <remarks>
/// Só devolve uma versão quando ela vem explicitamente no banner. Nunca adivinha: sem versão,
/// a verificação de vulnerabilidades fica marcada como "versão desconhecida" em vez de inventar resultados.
/// </remarks>
public static class BannerParser
{
    public sealed record ParsedBanner(
        string ProductKey,
        string ProductName,
        string Version,
        bool IsDistroPackage,
        string DistroName);

    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // Nomes que indicam um pacote de distribuição (correções aplicadas sem mudar a versão upstream).
    // Os sufixos de pacote ("0ubuntu0.20.04", "+deb11u2", "-1.el8") aparecem colados a dígitos,
    // por isso não levam \b (não há fronteira de palavra entre "0" e "ubuntu").
    private static readonly Regex DistroRegex = new(
        @"\b(?:Ubuntu|Debian|Raspbian|Red\s?Hat|RHEL|CentOS|Rocky|AlmaLinux|Fedora|SUSE|openSUSE|Amazon|Alpine|FreeBSD|Gentoo|Arch\b|Oracle\s?Linux)|ubuntu\d|deb\d+u\d+|\.el\d+",
        Opts);

    /// <summary>
    /// Interpreta um banner. <paramref name="port"/> ajuda a escolher o protocolo quando o banner é ambíguo.
    /// Devolve <c>null</c> se não reconhecer o produto.
    /// </summary>
    public static ParsedBanner? Parse(string? banner, int port)
    {
        if (string.IsNullOrWhiteSpace(banner))
            return null;

        return ParseDns(banner)
               ?? ParseSsh(banner)
               ?? ParseHttp(banner)
               ?? ParseFtp(banner)
               ?? ParseSmtp(banner)
               ?? ParseMySql(banner, port)
               ?? ParseRedis(banner);
    }

    // DNS (resposta a version.bind, ver DnsVersionProbe):
    // "dnsmasq-2.80", "dnsmasq-pi-hole-v2.90", "unbound 1.13.1", "9.18.18-0ubuntu0.22.04.1-Ubuntu" (BIND)
    private static ParsedBanner? ParseDns(string banner)
    {
        if (!banner.StartsWith(NetworkScanner.Services.DnsVersionProbe.BannerPrefix, StringComparison.Ordinal))
            return null;

        var value = banner[NetworkScanner.Services.DnsVersionProbe.BannerPrefix.Length..].Trim();

        var dnsmasq = Regex.Match(value, @"^dnsmasq-(?<pihole>pi-hole-)?v?(?<v>\d+\.\d+(?:\.\d+)?(?:(?:test|rc)\d+)?)", Opts);
        if (dnsmasq.Success)
        {
            var piHole = dnsmasq.Groups["pihole"].Success;
            return new ParsedBanner("dnsmasq", piHole ? "dnsmasq (Pi-hole FTL)" : "dnsmasq",
                dnsmasq.Groups["v"].Value, piHole, piHole ? "Pi-hole" : "");
        }

        var unbound = Regex.Match(value, @"^unbound (?<v>\d+\.\d+\.\d+)", Opts);
        if (unbound.Success)
            return new ParsedBanner("unbound", "Unbound", unbound.Groups["v"].Value, false, "");

        // BIND: "9.16.1-Ubuntu", "9.11.4-P2-RedHat-9.11.4-26.P2.el7"
        var bind = Regex.Match(value, @"^(?<v>9\.\d+\.\d+(?:-P\d+)?)(?<rest>.*)$", Opts);
        if (bind.Success)
        {
            var (distro, name) = DetectDistro(bind.Groups["rest"].Value);
            return new ParsedBanner("bind", "ISC BIND", bind.Groups["v"].Value, distro, name);
        }

        // Servidor respondeu mas esconde a versão (ex.: "none", "unknown", texto livre).
        return new ParsedBanner("", "DNS", "", false, "");
    }

    // SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "SSH-2.0-dropbear_2022.83"
    private static ParsedBanner? ParseSsh(string banner)
    {
        var line = Regex.Match(banner, @"SSH-[\d.]+-(?<soft>\S+)(?:[ \t]+(?<comment>[^\r\n]*))?", Opts);
        if (!line.Success)
            return null;

        var software = line.Groups["soft"].Value;
        var comment = line.Groups["comment"].Value;

        var openssh = Regex.Match(software, @"^OpenSSH_(?<win>for_Windows_)?(?<v>\d+\.\d+(?:\.\d+)?(?:p\d+)?)", Opts);
        if (openssh.Success)
        {
            var isWindows = openssh.Groups["win"].Success;
            var (distro, name) = DetectDistro(comment);
            if (isWindows)
            {
                distro = true;
                name = "Windows";
            }
            return new ParsedBanner("openssh", isWindows ? "OpenSSH for Windows" : "OpenSSH",
                openssh.Groups["v"].Value, distro, name);
        }

        var dropbear = Regex.Match(software, @"^dropbear_(?<v>\d{4}\.\d+)", Opts);
        if (dropbear.Success)
        {
            var (distro, name) = DetectDistro(comment);
            return new ParsedBanner("dropbear", "Dropbear SSH", dropbear.Groups["v"].Value, distro, name);
        }

        // SSH reconhecido mas produto desconhecido: devolve o nome sem versão verificável.
        return new ParsedBanner("", software.Split('_')[0], "", false, "");
    }

    // HTTP: cabeçalho "Server: Apache/2.4.41 (Ubuntu)", "nginx/1.18.0", "Microsoft-IIS/10.0", "Jetty(9.4.z)"
    private static ParsedBanner? ParseHttp(string banner)
    {
        if (!banner.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            return null;

        var server = Regex.Match(banner, @"^Server:[ \t]*(?<s>[^\r\n]+)", Opts | RegexOptions.Multiline);
        if (!server.Success)
            return new ParsedBanner("", "HTTP", "", false, "");

        var value = server.Groups["s"].Value.Trim();
        var (distro, distroName) = DetectDistro(value);

        // UPnP de routers: "Linux/4.14 UPnP/1.0 MiniUPnPd/2.2.1" (o produto não vem no início).
        var miniupnpd = Regex.Match(value, @"\bMiniUPnPd/(?<v>\d+\.\d+(?:\.\d+)?)", Opts);
        if (miniupnpd.Success)
            return new ParsedBanner("miniupnpd", "MiniUPnPd", miniupnpd.Groups["v"].Value, false, "");

        (string Key, string Name, string Pattern)[] patterns =
        [
            ("apache_httpd", "Apache HTTP Server", @"^Apache/(?<v>\d+\.\d+\.\d+)"),
            ("nginx", "nginx", @"^nginx/(?<v>\d+\.\d+\.\d+)"),
            ("iis", "Microsoft IIS", @"^Microsoft-IIS/(?<v>\d+\.\d+)"),
            ("lighttpd", "lighttpd", @"^lighttpd/(?<v>\d+\.\d+\.\d+)"),
            ("jetty", "Eclipse Jetty", @"Jetty\((?<v>\d+\.\d+\.\d+)"),
        ];

        foreach (var (key, name, pattern) in patterns)
        {
            var m = Regex.Match(value, pattern, Opts);
            if (m.Success)
                return new ParsedBanner(key, name, m.Groups["v"].Value, distro, distroName);
        }

        // Produto conhecido mas sem versão (ex.: "Server: nginx", "Server: Apache").
        // O nome tem de terminar ali: "Apache-Coyote" (Tomcat) não é o Apache HTTP Server.
        (string Key, string Name, string Bare)[] bareNames =
        [
            ("apache_httpd", "Apache HTTP Server", "Apache"),
            ("nginx", "nginx", "nginx"),
            ("iis", "Microsoft IIS", "Microsoft-IIS"),
            ("lighttpd", "lighttpd", "lighttpd"),
            ("jetty", "Eclipse Jetty", "Jetty"),
        ];
        foreach (var (key, name, bare) in bareNames)
        {
            if (Regex.IsMatch(value, $@"^{Regex.Escape(bare)}(?:$|[\s/(])", Opts))
                return new ParsedBanner(key, name, "", distro, distroName);
        }

        return new ParsedBanner("", value.Split('/', ' ')[0], "", distro, distroName);
    }

    // FTP: "220 (vsFTPd 3.0.3)", "220 ProFTPD 1.3.5e Server", "220-FileZilla Server 1.7.0"
    private static ParsedBanner? ParseFtp(string banner)
    {
        if (!Regex.IsMatch(banner, @"^220[ -]", Opts))
            return null;

        var vsftpd = Regex.Match(banner, @"vsFTPd (?<v>\d+\.\d+\.\d+)", Opts);
        if (vsftpd.Success)
            return new ParsedBanner("vsftpd", "vsftpd", vsftpd.Groups["v"].Value, false, "");

        var proftpd = Regex.Match(banner, @"ProFTPD (?<v>\d+\.\d+\.\d+[a-z]?)", Opts);
        if (proftpd.Success)
        {
            var (distro, name) = DetectDistro(banner);
            return new ParsedBanner("proftpd", "ProFTPD", proftpd.Groups["v"].Value, distro, name);
        }

        var filezilla = Regex.Match(banner, @"FileZilla Server(?: version)? (?<v>\d+\.\d+\.\d+)", Opts);
        if (filezilla.Success)
            return new ParsedBanner("filezilla_server", "FileZilla Server", filezilla.Groups["v"].Value, false, "");

        return null; // pode ser SMTP (também começa por 220)
    }

    // SMTP: "220 mail.example.com ESMTP Exim 4.94.2 ..."; Postfix não anuncia versão.
    private static ParsedBanner? ParseSmtp(string banner)
    {
        if (!Regex.IsMatch(banner, @"^220[ -]", Opts))
            return null;

        var exim = Regex.Match(banner, @"\bExim (?<v>\d+\.\d+(?:\.\d+)?)", Opts);
        if (exim.Success)
        {
            var (distro, name) = DetectDistro(banner);
            return new ParsedBanner("exim", "Exim", exim.Groups["v"].Value, distro, name);
        }

        if (banner.Contains("Postfix", StringComparison.OrdinalIgnoreCase))
            return new ParsedBanner("", "Postfix", "", false, "");

        return null;
    }

    // MySQL/MariaDB: pacote de handshake (protocolo 10) seguido da versão terminada em \0.
    // MariaDB anuncia "5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1" (o prefixo 5.5.5- é um artefacto de compatibilidade).
    private static ParsedBanner? ParseMySql(string banner, int port)
    {
        var mariadb = Regex.Match(banner, @"(?:5\.5\.5-)?(?<v>\d+\.\d+\.\d+)-MariaDB(?<rest>[^\0]*)", Opts);
        if (mariadb.Success)
        {
            var (distro, name) = DetectDistro(mariadb.Groups["rest"].Value);
            return new ParsedBanner("mariadb", "MariaDB", mariadb.Groups["v"].Value, distro, name);
        }

        // Handshake: 4 bytes de cabeçalho + 0x0A + versão\0
        var handshake = banner.Length > 5 && banner[4] == '\n';
        if (!handshake && port != 3306)
            return null;

        var mysql = Regex.Match(handshake ? banner[5..] : banner, @"^(?<v>\d+\.\d+\.\d+)(?<rest>[^\0]*)", Opts);
        if (!mysql.Success)
            return null;

        var (isDistro, distroName) = DetectDistro(mysql.Groups["rest"].Value);
        return new ParsedBanner("mysql", "MySQL", mysql.Groups["v"].Value, isDistro, distroName);
    }

    // Redis: resposta a "INFO server" contém "redis_version:7.0.11".
    private static ParsedBanner? ParseRedis(string banner)
    {
        var m = Regex.Match(banner, @"redis_version:(?<v>\d+\.\d+\.\d+)", Opts);
        if (m.Success)
            return new ParsedBanner("redis", "Redis", m.Groups["v"].Value, false, "");

        if (banner.StartsWith("-NOAUTH", StringComparison.OrdinalIgnoreCase) ||
            banner.StartsWith("+PONG", StringComparison.OrdinalIgnoreCase))
            return new ParsedBanner("redis", "Redis", "", false, "");

        return null;
    }

    private static (bool IsDistro, string Name) DetectDistro(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return (false, "");
        var m = DistroRegex.Match(text);
        if (!m.Success)
            return (false, "");

        var raw = m.Value;
        var name = raw.StartsWith("deb", StringComparison.OrdinalIgnoreCase) ? "Debian"
            : raw.StartsWith("ubuntu", StringComparison.OrdinalIgnoreCase) ? "Ubuntu"
            : raw.StartsWith(".el", StringComparison.OrdinalIgnoreCase) ? "Enterprise Linux"
            : raw;
        return (true, name);
    }
}
