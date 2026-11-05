using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Nodar.Core.Services;
using Nodar.Core.Services.Vulnerabilities;

namespace Nodar.Tests;

public class DnsVersionProbeTests
{
    /// <summary>Resposta como a do dnsmasq: pergunta repetida + resposta com ponteiro para o nome (0xC00C).</summary>
    private static byte[] BuildResponse(byte[] query, string txt, ushort flags = 0x8400, int answers = 1)
    {
        var response = new List<byte>(query);
        BinaryPrimitives.WriteUInt16BigEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(response)[2..], flags);
        BinaryPrimitives.WriteUInt16BigEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(response)[6..], (ushort)answers);

        for (var i = 0; i < answers; i++)
        {
            var text = Encoding.ASCII.GetBytes(txt);
            response.AddRange([0xC0, 0x0C]);            // nome: ponteiro para a pergunta
            response.AddRange([0x00, 0x10]);            // TXT
            response.AddRange([0x00, 0x03]);            // CH
            response.AddRange([0x00, 0x00, 0x00, 0x00]); // TTL
            var rdLength = (ushort)(text.Length + 1);
            response.AddRange([(byte)(rdLength >> 8), (byte)rdLength]);
            response.Add((byte)text.Length);
            response.AddRange(text);
        }
        return response.ToArray();
    }

    [Fact]
    public void Query_is_version_bind_chaos_txt()
    {
        var q = DnsVersionProbe.BuildQuery(0x1234);
        Assert.Equal(0x1234, BinaryPrimitives.ReadUInt16BigEndian(q));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(4)));
        // \x07version\x04bind\x00 + TXT(16) + CH(3)
        var expectedTail = new byte[] { 7, (byte)'v', (byte)'e', (byte)'r', (byte)'s', (byte)'i', (byte)'o', (byte)'n',
                                        4, (byte)'b', (byte)'i', (byte)'n', (byte)'d', 0, 0, 16, 0, 3 };
        Assert.Equal(expectedTail, q[12..]);
    }

    [Fact]
    public void Parses_dnsmasq_response()
    {
        var q = DnsVersionProbe.BuildQuery(42);
        Assert.Equal("dnsmasq-2.80", DnsVersionProbe.ParseResponse(BuildResponse(q, "dnsmasq-2.80"), 42));
    }

    [Fact]
    public void Rejects_wrong_id_error_rcode_and_queries()
    {
        var q = DnsVersionProbe.BuildQuery(42);
        Assert.Null(DnsVersionProbe.ParseResponse(BuildResponse(q, "dnsmasq-2.80"), 43));               // outro ID
        Assert.Null(DnsVersionProbe.ParseResponse(BuildResponse(q, "x", flags: 0x8405), 42));           // REFUSED
        Assert.Null(DnsVersionProbe.ParseResponse(BuildResponse(q, "x", flags: 0x0000), 42));           // não é resposta
        Assert.Null(DnsVersionProbe.ParseResponse(BuildResponse(q, "", answers: 0), 42));               // sem respostas
    }

    [Fact]
    public void Truncated_or_garbage_packets_do_not_throw()
    {
        var q = DnsVersionProbe.BuildQuery(42);
        var full = BuildResponse(q, "dnsmasq-2.80");
        for (var len = 0; len < full.Length; len++)
            Assert.Null(DnsVersionProbe.ParseResponse(full.AsSpan(0, len), 42));

        var random = new Random(1);
        for (var i = 0; i < 500; i++)
        {
            var junk = new byte[random.Next(0, 80)];
            random.NextBytes(junk);
            DnsVersionProbe.ParseResponse(junk, 42); // não pode lançar exceção
        }
    }

    [Fact]
    public async Task Queries_a_local_udp_server()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        var serverTask = Task.Run(async () =>
        {
            var request = await server.ReceiveAsync();
            await server.SendAsync(BuildResponse(request.Buffer, "dnsmasq-2.90"), request.RemoteEndPoint);
        });

        var version = await DnsVersionProbe.QueryAsync("127.0.0.1", CancellationToken.None, TimeSpan.FromSeconds(2), port);
        Assert.Equal("dnsmasq-2.90", version);
    }

    [Fact]
    public async Task Silent_dns_server_times_out()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        Assert.Null(await DnsVersionProbe.QueryAsync("127.0.0.1", CancellationToken.None, TimeSpan.FromMilliseconds(300), port));
    }

    [Theory]
    [InlineData("dnsmasq-2.80", "dnsmasq", "2.80", false)]
    [InlineData("dnsmasq-2.89", "dnsmasq", "2.89", false)]
    [InlineData("dnsmasq-pi-hole-v2.90+1", "dnsmasq", "2.90", true)]
    [InlineData("dnsmasq-pi-hole-2.87test8", "dnsmasq", "2.87test8", true)]
    [InlineData("unbound 1.13.1", "unbound", "1.13.1", false)]
    [InlineData("9.18.18-0ubuntu0.22.04.1-Ubuntu", "bind", "9.18.18", true)]
    [InlineData("9.11.4-P2-RedHat-9.11.4-26.P2.el7", "bind", "9.11.4-P2", true)]
    public void Parses_dns_versions(string txt, string key, string version, bool distro)
    {
        var r = BannerParser.Parse(DnsVersionProbe.BannerPrefix + txt, 53);
        Assert.Equal(key, r!.ProductKey);
        Assert.Equal(version, r.Version);
        Assert.Equal(distro, r.IsDistroPackage);
    }

    [Fact]
    public void Hidden_dns_version_is_not_guessed()
    {
        var r = BannerParser.Parse(DnsVersionProbe.BannerPrefix + "none of your business", 53);
        Assert.Equal("", r!.ProductKey);
        Assert.Equal("", r.Version);
    }

    [Fact]
    public void Pihole_test_build_is_older_than_release()
    {
        Assert.True(VersionComparer.Compare("2.87test8", "2.87") < 0);
        Assert.True(VersionComparer.Compare("2.87test8", "2.86") > 0);
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nSERVER: Linux/4.14.76 UPnP/1.0 MiniUPnPd/2.2.1\r\n\r\n", "2.2.1")]
    [InlineData("HTTP/1.1 200 OK\r\nServer: Linux/2.6 UPnP/1.0 miniupnpd/1.0\r\n\r\n", "1.0")]
    public void Parses_miniupnpd(string banner, string version)
    {
        var r = BannerParser.Parse(banner, 49152);
        Assert.Equal("miniupnpd", r!.ProductKey);
        Assert.Equal(version, r.Version);
    }

    [Fact]
    public void Bind_patch_level_matches_nvd_update_field()
    {
        // NVD regista o BIND como version=9.11.4, update=p2
        var rule = new CpeMatchRule { Version = "9.11.4", Update = "p2" };
        Assert.True(CpeMatcher.Matches(rule, "9.11.4-P2"));
        Assert.False(CpeMatcher.Matches(rule, "9.11.4-P3"));
        Assert.True(VersionComparer.Compare("9.11.4-P2", "9.11.5") < 0);
        Assert.True(VersionComparer.Compare("9.11.4-P2", "9.11.4") > 0);
    }
}
