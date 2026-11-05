namespace Nodar.Core.Services.Vulnerabilities;

/// <summary>
/// Produtos que o Nodar sabe identificar por banner e os respetivos identificadores CPE na NVD.
/// </summary>
/// <remarks>
/// Cada par vendor:product foi confirmado na API da NVD (pesquisas com <c>virtualMatchString</c> que devolvem CVEs).
/// Alguns produtos têm mais do que um identificador porque a NVD mudou o fabricante ao longo do tempo
/// (ex.: nginx passou a <c>f5:nginx</c>).
/// </remarks>
public static class ProductCatalog
{
    public sealed record Product(string Key, string DisplayName, IReadOnlyList<(string Vendor, string Product)> Cpes);

    private static readonly Product[] Products =
    [
        new("openssh", "OpenSSH", [("openbsd", "openssh")]),
        new("dropbear", "Dropbear SSH", [("dropbear_ssh_project", "dropbear_ssh")]),
        new("apache_httpd", "Apache HTTP Server", [("apache", "http_server")]),
        new("nginx", "nginx", [("f5", "nginx"), ("nginx", "nginx")]),
        new("iis", "Microsoft IIS", [("microsoft", "internet_information_services")]),
        new("lighttpd", "lighttpd", [("lighttpd", "lighttpd")]),
        new("jetty", "Eclipse Jetty", [("eclipse", "jetty")]),
        new("vsftpd", "vsftpd", [("beasts", "vsftpd"), ("vsftpd_project", "vsftpd")]),
        new("proftpd", "ProFTPD", [("proftpd", "proftpd")]),
        new("filezilla_server", "FileZilla Server", [("filezilla-project", "filezilla_server")]),
        new("exim", "Exim", [("exim", "exim")]),
        new("mysql", "MySQL", [("oracle", "mysql"), ("mysql", "mysql")]),
        new("mariadb", "MariaDB", [("mariadb", "mariadb")]),
        new("redis", "Redis", [("redis", "redis")]),
        new("dnsmasq", "dnsmasq", [("thekelleys", "dnsmasq")]),
        new("unbound", "Unbound", [("nlnetlabs", "unbound")]),
        new("bind", "ISC BIND", [("isc", "bind")]),
        new("miniupnpd", "MiniUPnPd", [("miniupnp_project", "miniupnpd")]),
        // "Portable SDK for UPnP devices" (libupnp, hoje pupnp): muito usada em firmware de routers.
        new("libupnp", "libupnp (Portable UPnP SDK)", [("libupnp_project", "libupnp"), ("pupnp_project", "pupnp")]),
    ];

    private static readonly Dictionary<string, Product> ByKey =
        Products.ToDictionary(p => p.Key, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<Product> All => Products;

    public static Product? Find(string? key) =>
        !string.IsNullOrEmpty(key) && ByKey.TryGetValue(key, out var product) ? product : null;
}
