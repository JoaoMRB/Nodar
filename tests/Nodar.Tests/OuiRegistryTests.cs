using Nodar.Core.Services;

namespace Nodar.Tests;

[Collection("OuiRegistry")] // estado estático partilhado
public class OuiRegistryTests
{
    private const string Sample = """
        Registry,Assignment,Organization Name,Organization Address
        MA-L,FC039F,"Samsung Electronics Co.,Ltd","129, Samsung-ro, Suwon KR 16677 "
        MA-L,8CDEF9,"Beijing Xiaomi Mobile Software Co., Ltd","The Rainbow City, Beijing CN 100085 "
        MA-L,BCFCE7,ASUSTek COMPUTER INC.,"15,Li-Te Rd., Taipei TW 112 "
        MA-L,D8D668,Tuya Smart Inc.,"160 Greentree Drive, Dover DE US 19904 "
        MA-L,580D0D,"GREE ELECTRIC APPLIANCES, INC. OF ZHUHAI","West Jinji Rd, Zhuhai CN 519070 "
        MA-L,ABCDEF,"ACME WIDGET TECHNOLOGY CO., LTD.","Somewhere CN "
        MA-L,123456,"Quote ""Inside"" Systems GmbH","Berlin DE "
        """;

    [Fact]
    public void Parses_ieee_csv_with_quoted_commas()
    {
        var table = OuiRegistry.ParseCsv(Sample);
        Assert.Equal(7, table.Count);
        Assert.Equal("Samsung", table["FC039F"]);
        Assert.Equal("Xiaomi", table["8CDEF9"]);
        Assert.Equal("ASUS", table["BCFCE7"]);
        Assert.Equal("Tuya", table["D8D668"]);
        Assert.Equal("Gree", table["580D0D"]);
    }

    [Theory]
    [InlineData("ACME WIDGET TECHNOLOGY CO., LTD.", "Acme Widget")]
    [InlineData("Quote \"Inside\" Systems GmbH", "Quote \"Inside\"")]
    [InlineData("Seiko Epson Corporation", "Epson")]
    [InlineData("Hon Hai Precision Ind. Co.,Ltd.", "Foxconn")]
    [InlineData("Shenzhen Foo Bar Co., Ltd", "Shenzhen Foo Bar")]
    public void Shortens_organization_names(string organization, string expected) =>
        Assert.Equal(expected, OuiRegistry.ShortName(organization));

    [Fact]
    public void Vendor_lookup_prefers_the_official_registry()
    {
        try
        {
            OuiRegistry.SetTableForTests(OuiRegistry.ParseCsv(Sample));
            Assert.Equal("Samsung", VendorService.Lookup("FC:03:9F:00:00:01"));
            Assert.Equal("Tuya", VendorService.Lookup("D8-D6-68-00-00-01"));
            Assert.Equal("Smart Home", VendorService.GetDeviceType(VendorService.Lookup("D8:D6:68:00:00:01"), ""));
        }
        finally
        {
            OuiRegistry.SetTableForTests(null);
        }
    }
}
