using System.Buffers.Binary;
using System.Text;
using System.Xml;
using Nodar.Core.Services;
using Nodar.Core.Services.Vulnerabilities;

namespace Nodar.Tests;

public class SsdpTests
{
    private const string RouterDescriptor = """
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <specVersion><major>1</major><minor>0</minor></specVersion>
          <device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <friendlyName>TP-Link Archer AX55</friendlyName>
            <manufacturer>TP-Link</manufacturer>
            <modelName>Archer AX55</modelName>
            <modelNumber>3</modelNumber>
            <deviceList>
              <device>
                <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
                <friendlyName>WANDevice</friendlyName>
                <manufacturer>Outro</manufacturer>
              </device>
            </deviceList>
          </device>
        </root>
        """;

    [Fact]
    public void Parses_ssdp_response_headers()
    {
        var headers = SsdpProbe.ParseHeaders(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:49152/desc.xml\r\n" +
            "SERVER: Linux/4.19, UPnP/1.0, Portable SDK for UPnP devices/1.6.21\r\nST: upnp:rootdevice\r\n\r\n");
        Assert.Equal("http://192.168.1.1:49152/desc.xml", headers["location"]);
        Assert.Equal("upnp:rootdevice", headers["ST"]);
        Assert.Contains("Portable SDK", headers["SERVER"]);
    }

    [Fact]
    public void Reads_root_device_fields_not_sub_devices()
    {
        var id = new SsdpProbe.Identity { Ip = "192.168.1.1" };
        SsdpProbe.ApplyDescriptor(id, RouterDescriptor);
        Assert.Equal("TP-Link Archer AX55", id.FriendlyName);
        Assert.Equal("TP-Link", id.Manufacturer);
        Assert.Equal("Archer AX55", id.ModelName);
        Assert.Contains("InternetGatewayDevice", id.DeviceType);

        var d = DeviceIdentification.Describe(id);
        Assert.Equal("TP-Link Archer AX55", d.Model);
        Assert.Null(d.FriendlyName); // o friendlyName é só o modelo: não é um nome
        Assert.Equal("Router", d.DeviceType);
        Assert.Equal("TP-Link", d.Vendor);
    }

    [Fact]
    public void External_entities_are_refused()
    {
        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE root [ <!ENTITY x SYSTEM "file:///C:/Windows/win.ini"> ]>
            <root><device><friendlyName>&x;</friendlyName></device></root>
            """;
        var id = new SsdpProbe.Identity { Ip = "10.0.0.1" };
        Assert.Throws<XmlException>(() => SsdpProbe.ApplyDescriptor(id, xxe));
        Assert.Null(id.FriendlyName);
    }

    [Fact]
    public void Chromecast_tv_is_a_tv_with_real_manufacturer()
    {
        var id = new SsdpProbe.Identity
        {
            Ip = "192.168.1.11", FriendlyName = "TV da Sala", Manufacturer = "Xiaomi", ModelName = "MiTV-X1",
            DeviceType = "urn:dial-multiscreen-org:device:dial:1", Server = "Linux/4.19, UPnP/1.0, Chromecast/1.6.18"
        };
        var d = DeviceIdentification.Describe(id);
        Assert.Equal("TV", d.DeviceType);
        Assert.Equal("Xiaomi MiTV-X1", d.Model);
        Assert.Equal("TV da Sala", d.FriendlyName);
    }

    [Theory]
    [InlineData("Linux/4.19.183, UPnP/1.0, Portable SDK for UPnP devices/1.6.21", "libupnp", "1.6.21")]
    [InlineData("Linux/3.4 UPnP/1.0 MiniUPnPd/2.1", "miniupnpd", "2.1")]
    [InlineData("Linux/4.19 UPnP/1.0 Chromecast/1.6.18", "", "")]
    public void Ssdp_server_header_is_a_checkable_service(string server, string key, string version)
    {
        var s = ServiceDetectionService.FromBanner(1900, "UPnP (SSDP)", BannerParser.SsdpPrefix + server);
        Assert.Equal(key, s.ProductKey);
        Assert.Equal(version, s.Version);
        Assert.Equal(1900, s.Port);
    }

    [Fact]
    public void Libupnp_is_in_the_catalog_with_both_cpe_names() =>
        Assert.Equal(2, ProductCatalog.Find("libupnp")!.Cpes.Count);
}

public class NetBiosTests
{
    [Fact]
    public void Node_status_request_encodes_wildcard_name()
    {
        var q = NetBiosProbe.BuildNodeStatusRequest(0x1234);
        Assert.Equal(50, q.Length);
        Assert.Equal(32, q[12]);
        Assert.Equal((byte)'C', q[13]); // '*' = 0x2A → 'C','K'
        Assert.Equal((byte)'K', q[14]);
        Assert.Equal((byte)'A', q[15]);
        Assert.Equal(0x21, BinaryPrimitives.ReadUInt16BigEndian(q.AsSpan(46)));
    }

    private static byte[] Response(ushort id, params (string Name, byte Suffix, bool Group)[] names)
    {
        var p = new List<byte>();
        p.AddRange([(byte)(id >> 8), (byte)id, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
        p.AddRange(NetBiosProbe.BuildNodeStatusRequest(id)[12..46]); // nome codificado (34 bytes)
        p.AddRange([0, 0x21, 0, 1, 0, 0, 0, 0]);                   // tipo, classe, TTL
        var rd = new List<byte> { (byte)names.Length };
        foreach (var (name, suffix, group) in names)
        {
            rd.AddRange(Encoding.ASCII.GetBytes(name.PadRight(15)));
            rd.Add(suffix);
            rd.AddRange([(byte)(group ? 0x84 : 0x04), 0x00]);
        }
        rd.AddRange(new byte[6]); // MAC
        p.AddRange([(byte)(rd.Count >> 8), (byte)rd.Count]);
        p.AddRange(rd);
        return p.ToArray();
    }

    [Fact]
    public void Reads_computer_name_and_workgroup()
    {
        var packet = Response(7, ("DESKTOP-ANA", 0x00, false), ("WORKGROUP", 0x00, true), ("DESKTOP-ANA", 0x20, false));
        var n = NetBiosProbe.ParseNodeStatus(packet, 7, "192.168.1.50");
        Assert.NotNull(n);
        Assert.Equal("DESKTOP-ANA", n!.ComputerName);
        Assert.Equal("WORKGROUP", n.Workgroup);
    }

    [Fact]
    public void Wrong_id_or_truncated_packets_are_ignored()
    {
        var packet = Response(7, ("PC", 0x00, false));
        Assert.Null(NetBiosProbe.ParseNodeStatus(packet, 8, "1.1.1.1"));
        for (var len = 0; len < packet.Length - 1; len++)
            NetBiosProbe.ParseNodeStatus(packet.AsSpan(0, len), 7, "1.1.1.1"); // não lança
    }

    [Fact]
    public void Combine_prefers_mdns_name_then_ssdp_then_netbios()
    {
        var mdns = new MdnsProbe.Identity { Ip = "1.1.1.1", FriendlyName = "MacBook Pro da Ana", ModelId = "Mac14,7" };
        var netbios = new NetBiosProbe.Names("1.1.1.1", "MAC-586A67", null);
        var d = DeviceIdentification.Combine(mdns, null, netbios)!;
        Assert.Equal("MacBook Pro da Ana", d.FriendlyName);
        Assert.Equal("Computador", d.DeviceType);

        var onlyNetbios = DeviceIdentification.Combine(null, null, new NetBiosProbe.Names("2.2.2.2", "DESKTOP-ANA", "WORKGROUP"))!;
        Assert.Equal("DESKTOP-ANA", onlyNetbios.FriendlyName);

        Assert.Null(DeviceIdentification.Combine(null, null, null));
    }
}
