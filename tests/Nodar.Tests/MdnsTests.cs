using System.Text;
using Nodar.Core.Services;

namespace Nodar.Tests;

/// <summary>Construtor mínimo de respostas mDNS para testes (sem compressão de nomes nos dados).</summary>
internal sealed class MdnsPacket
{
    private readonly List<byte> _records = [];
    private int _count;

    private static byte[] Name(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var data = Encoding.UTF8.GetBytes(label);
            bytes.Add((byte)data.Length);
            bytes.AddRange(data);
        }
        bytes.Add(0);
        return bytes.ToArray();
    }

    private MdnsPacket Add(string name, ushort type, byte[] rdata)
    {
        _records.AddRange(Name(name));
        _records.AddRange([(byte)(type >> 8), (byte)type, 0x80, 0x01, 0, 0, 0, 120, (byte)(rdata.Length >> 8), (byte)rdata.Length]);
        _records.AddRange(rdata);
        _count++;
        return this;
    }

    public MdnsPacket Ptr(string name, string target) => Add(name, 12, Name(target));
    public MdnsPacket Srv(string name, string target) => Add(name, 33, [0, 0, 0, 0, 0x1F, 0x90, .. Name(target)]);
    public MdnsPacket A(string name, string ip) => Add(name, 1, ip.Split('.').Select(byte.Parse).ToArray());
    public MdnsPacket Txt(string name, params string[] entries) =>
        Add(name, 16, entries.SelectMany(e => { var d = Encoding.UTF8.GetBytes(e); return new[] { (byte)d.Length }.Concat(d); }).ToArray());

    public byte[] Build() =>
        [0, 0, 0x84, 0x00, 0, 0, (byte)(_count >> 8), (byte)_count, 0, 0, 0, 0, .. _records];
}

public class MdnsTests
{
    [Fact]
    public void Mac_announcing_airplay_and_device_info_is_identified()
    {
        var packet = new MdnsPacket()
            .Ptr("_device-info._tcp.local", "MacBook Pro da Ana._device-info._tcp.local")
            .Txt("MacBook Pro da Ana._device-info._tcp.local", "model=Mac14,7", "osxvers=24")
            .Build();

        var id = Assert.Single(MdnsProbe.ParseResponse(packet, "192.168.1.34"));
        Assert.Equal("192.168.1.34", id.Ip);
        Assert.Equal("MacBook Pro da Ana", id.FriendlyName);
        Assert.Equal("Mac14,7", id.ModelId);

        var d = DeviceIdentification.Describe(id);
        Assert.Equal("Mac", d.Model);
        Assert.Equal("Apple", d.Vendor);
        Assert.Equal("Computador", d.DeviceType);
    }

    [Fact]
    public void Reverse_lookup_gives_iphone_hostname()
    {
        var packet = new MdnsPacket()
            .Ptr("241.1.168.192.in-addr.arpa", "IPhone-de-Ana-Silva.local")
            .Build();

        var id = Assert.Single(MdnsProbe.ParseResponse(packet, "192.168.1.241"));
        Assert.Equal("IPhone-de-Ana-Silva.local", id.Hostname);

        var d = DeviceIdentification.Describe(id);
        Assert.Equal("iPhone de Ana Silva", d.FriendlyName);
        Assert.Equal("iPhone", d.Model);
        Assert.Equal("Apple", d.DeviceType);
    }

    [Fact]
    public void Chromecast_uses_fn_not_the_technical_instance_name()
    {
        var packet = new MdnsPacket()
            .Ptr("_googlecast._tcp.local", "MiTV-X1-0123456789abcdef._googlecast._tcp.local")
            .Txt("MiTV-X1-0123456789abcdef._googlecast._tcp.local", "md=MiTV-X1", "fn=TV da Sala")
            .Build();

        var id = Assert.Single(MdnsProbe.ParseResponse(packet, "192.168.1.11"));
        Assert.Equal("TV da Sala", id.FriendlyName);
        Assert.Equal("TV", DeviceIdentification.Describe(id).DeviceType);
    }

    [Fact]
    public void Sleep_proxy_answer_is_attributed_via_srv_and_a_records()
    {
        // Um Apple TV (192.168.1.50) responde em nome do Mac a dormir (192.168.1.34).
        var packet = new MdnsPacket()
            .Ptr("_companion-link._tcp.local", "Mac da Ana._companion-link._tcp.local")
            .Srv("Mac da Ana._companion-link._tcp.local", "Mac-da-Ana.local")
            .Txt("Mac da Ana._companion-link._tcp.local", "rpMd=MacBookAir10,1")
            .A("Mac-da-Ana.local", "192.168.1.34")
            .Build();

        var ids = MdnsProbe.ParseResponse(packet, "192.168.1.50");
        var mac = Assert.Single(ids, i => i.Ip == "192.168.1.34");
        Assert.Equal("MacBookAir10,1", mac.ModelId);
        Assert.Equal("Mac-da-Ana.local", mac.Hostname);
        Assert.DoesNotContain(ids, i => i.Ip == "192.168.1.50" && i.ModelId != null);
        Assert.Equal("MacBook Air", DeviceIdentification.Describe(mac).Model);
    }

    [Fact]
    public void Compressed_names_are_decoded()
    {
        // Cabeçalho + pergunta "a.local" em 12; resposta PTR com nome = ponteiro para 12.
        byte[] packet =
        [
            0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0,
            1, (byte)'a', 5, (byte)'l', (byte)'o', (byte)'c', (byte)'a', (byte)'l', 0, 0, 12, 0, 1,
            0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 10, 0, 4, 1, (byte)'b', 0xC0, 14
        ];
        var record = Assert.Single(MdnsProbe.ParseRecords(packet));
        Assert.Equal("a.local", record.Name);
        Assert.Equal("b.local", record.Target);
    }

    [Fact]
    public void Garbage_and_pointer_loops_do_not_throw()
    {
        byte[] loop = [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 12];
        Assert.Empty(MdnsProbe.ParseRecords(loop));

        var random = new Random(7);
        for (var i = 0; i < 1000; i++)
        {
            var junk = new byte[random.Next(0, 120)];
            random.NextBytes(junk);
            MdnsProbe.ParseResponse(junk, "10.0.0.1");
        }
    }

    [Fact]
    public void Queries_are_not_answers()
    {
        var query = MdnsProbe.BuildQuery(0, [("_device-info._tcp.local", 12)]);
        Assert.Empty(MdnsProbe.ParseRecords(query));
    }

    [Theory]
    [InlineData("MacBookPro18,3", "MacBook Pro", "Computador")]
    [InlineData("MacBookAir10,1", "MacBook Air", "Computador")]
    [InlineData("iMac21,1", "iMac", "Computador")]
    [InlineData("Macmini9,1", "Mac mini", "Computador")]
    [InlineData("Mac14,7", "Mac", "Computador")]
    [InlineData("iPhone15,2", "iPhone", "Apple")]
    [InlineData("iPad13,4", "iPad", "Apple")]
    [InlineData("AppleTV14,1", "Apple TV", "TV")]
    [InlineData("AudioAccessory5,1", "HomePod", "Smart Home")]
    [InlineData("Chromecast", "Chromecast", "TV")]
    [InlineData("EPSON ET-3850 Series", "EPSON ET-3850 Series", "Impressora")]
    public void Model_ids_map_to_families(string modelId, string model, string type)
    {
        var (m, _, t) = DeviceIdentification.FromModelId(modelId);
        Assert.Equal(model, m);
        Assert.Equal(type, t);
    }

    [Theory]
    [InlineData("MacBook-Pro-da-Ana-2.local", "MacBook Pro da Ana")]
    [InlineData("IPhone-de-Ana-Silva.local", "iPhone de Ana Silva")]
    [InlineData("homelab.local", "homelab")]
    public void Pretty_hostnames(string host, string expected) =>
        Assert.Equal(expected, DeviceIdentification.PrettyHostname(host));

    [Theory]
    [InlineData("D8:D6:68:00:00:01", true)]
    [InlineData("00000000-1111-2222-3333-444444444444.local", true)]
    [InlineData("", true)]
    [InlineData("iPhone.home", false)]
    public void Meaningless_hostnames(string host, bool expected) =>
        Assert.Equal(expected, DeviceIdentification.IsMeaninglessHostname(host));

    [Fact]
    public void Archer_repeater_is_a_router() =>
        Assert.Equal("Router", VendorService.GetDeviceType("Desconhecido", "Archer_C50.home"));
}
