using NetworkScanner.Services.Vulnerabilities;

namespace Nodar.Tests;

public class BannerParserTests
{
    [Theory]
    [InlineData("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", "openssh", "8.2p1", true, "Ubuntu")]
    [InlineData("SSH-2.0-OpenSSH_9.6\r\n", "openssh", "9.6", false, "")]
    [InlineData("SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n", "openssh", "7.9p1", true, "Debian")]
    [InlineData("SSH-2.0-OpenSSH_for_Windows_8.1\r\n", "openssh", "8.1", true, "Windows")]
    [InlineData("SSH-2.0-dropbear_2022.83\r\n", "dropbear", "2022.83", false, "")]
    public void Parses_ssh(string banner, string key, string version, bool distro, string distroName)
    {
        var r = BannerParser.Parse(banner, 22);
        Assert.NotNull(r);
        Assert.Equal(key, r!.ProductKey);
        Assert.Equal(version, r.Version);
        Assert.Equal(distro, r.IsDistroPackage);
        Assert.Equal(distroName, r.DistroName);
    }

    [Fact]
    public void Ssh_unknown_product_has_no_version()
    {
        var r = BannerParser.Parse("SSH-2.0-RomSShell_4.62\r\n", 22);
        Assert.NotNull(r);
        Assert.Equal("", r!.ProductKey);
        Assert.Equal("", r.Version);
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nDate: x\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n", "apache_httpd", "2.4.41", true)]
    [InlineData("HTTP/1.1 301 Moved\r\nServer: nginx/1.18.0\r\n\r\n", "nginx", "1.18.0", false)]
    [InlineData("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n", "iis", "10.0", false)]
    [InlineData("HTTP/1.1 200 OK\r\nserver: lighttpd/1.4.59\r\n\r\n", "lighttpd", "1.4.59", false)]
    [InlineData("HTTP/1.1 200 OK\r\nServer: Jetty(9.4.43.v20210629)\r\n\r\n", "jetty", "9.4.43", false)]
    public void Parses_http_server_header(string banner, string key, string version, bool distro)
    {
        var r = BannerParser.Parse(banner, 80);
        Assert.NotNull(r);
        Assert.Equal(key, r!.ProductKey);
        Assert.Equal(version, r.Version);
        Assert.Equal(distro, r.IsDistroPackage);
    }

    [Fact]
    public void Http_product_without_version()
    {
        var r = BannerParser.Parse("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", 80);
        Assert.Equal("nginx", r!.ProductKey);
        Assert.Equal("", r.Version);
    }

    [Fact]
    public void Tomcat_coyote_is_not_apache_httpd()
    {
        var r = BannerParser.Parse("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n", 8080);
        Assert.NotNull(r);
        Assert.NotEqual("apache_httpd", r!.ProductKey);
        Assert.Equal("", r.Version);
    }

    [Theory]
    [InlineData("220 (vsFTPd 3.0.3)\r\n", "vsftpd", "3.0.3")]
    [InlineData("220 ProFTPD 1.3.5e Server (Debian) [::ffff:10.0.0.2]\r\n", "proftpd", "1.3.5e")]
    [InlineData("220-FileZilla Server 1.7.0\r\n", "filezilla_server", "1.7.0")]
    [InlineData("220 FileZilla Server version 0.9.60 beta\r\n", "filezilla_server", "0.9.60")]
    public void Parses_ftp(string banner, string key, string version)
    {
        var r = BannerParser.Parse(banner, 21);
        Assert.Equal(key, r!.ProductKey);
        Assert.Equal(version, r.Version);
    }

    [Fact]
    public void Parses_exim_and_flags_postfix_without_version()
    {
        var exim = BannerParser.Parse("220 mail.example.com ESMTP Exim 4.94.2 Ubuntu Mon, 1 Jan 2024\r\n", 25);
        Assert.Equal("exim", exim!.ProductKey);
        Assert.Equal("4.94.2", exim.Version);
        Assert.True(exim.IsDistroPackage);

        var postfix = BannerParser.Parse("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", 25);
        Assert.Equal("", postfix!.ProductKey);
        Assert.Equal("Postfix", postfix.ProductName);
        Assert.Equal("", postfix.Version);
    }

    [Fact]
    public void Parses_mysql_handshake()
    {
        // 4 bytes de cabeçalho, protocolo 10 (0x0A), versão terminada em \0
        var banner = "J\0\0\0\n8.0.32-0ubuntu0.20.04.2\0xxxxmysql_native_password";
        var r = BannerParser.Parse(banner, 3306);
        Assert.Equal("mysql", r!.ProductKey);
        Assert.Equal("8.0.32", r.Version);
        Assert.True(r.IsDistroPackage);
    }

    [Fact]
    public void Parses_mariadb_with_compat_prefix()
    {
        var banner = "Y\0\0\0\n5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1\0rest";
        var r = BannerParser.Parse(banner, 3306);
        Assert.Equal("mariadb", r!.ProductKey);
        Assert.Equal("10.6.12", r.Version);
        Assert.True(r.IsDistroPackage);
    }

    [Theory]
    [InlineData("J\0\0\0\n8.0.36-1.el8\0x", "Enterprise Linux")]
    [InlineData("J\0\0\0\n8.0.36-0ubuntu0.22.04.1\0x", "Ubuntu")]
    [InlineData("J\0\0\0\n8.0.36\0x", "")]
    public void Detects_distro_suffixes(string banner, string distro)
    {
        var r = BannerParser.Parse(banner, 3306);
        Assert.Equal(distro, r!.DistroName);
        Assert.Equal(distro.Length > 0, r.IsDistroPackage);
    }

    [Fact]
    public void Architecture_word_is_not_arch_linux()
    {
        var r = BannerParser.Parse("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 Architecture\r\n\r\n", 80);
        Assert.False(r!.IsDistroPackage);
    }

    [Fact]
    public void Parses_redis_info()
    {
        var r = BannerParser.Parse("$3500\r\n# Server\r\nredis_version:7.0.11\r\nredis_git_sha1:00000000\r\n", 6379);
        Assert.Equal("redis", r!.ProductKey);
        Assert.Equal("7.0.11", r.Version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("random garbage")]
    public void Unknown_banners_return_null(string banner) =>
        Assert.Null(BannerParser.Parse(banner, 12345));
}
