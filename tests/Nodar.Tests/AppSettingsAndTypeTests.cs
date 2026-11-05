using System.Text.Json.Nodes;
using Nodar.Core.Services;
using Nodar.Core.Settings;

namespace Nodar.Tests;

public class AppSettingsAndTypeTests
{
    [Fact]
    public void Save_preserves_unknown_keys_like_nvd_api_key()
    {
        var path = Path.Combine(Path.GetTempPath(), "nodar-settings-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, """{ "nvdApiKey": "segredo", "deepScan": false }""");
            var s = AppSettings.Load(path);
            s.DeepScan = true;
            s.RefreshIntervalSeconds = 300;
            s.Save(path);

            var json = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
            Assert.Equal("segredo", (string?)json["nvdApiKey"]);
            Assert.True((bool)json["deepScan"]!);
            Assert.Equal(300, AppSettings.Load(path).RefreshIntervalSeconds);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Missing_or_corrupt_settings_use_defaults()
    {
        var path = Path.Combine(Path.GetTempPath(), "nodar-settings-" + Guid.NewGuid().ToString("N") + ".json");
        Assert.True(AppSettings.Load(path).PortScan);
        File.WriteAllText(path, "{oops");
        try { Assert.True(AppSettings.Load(path).PortScan); }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("Desconhecido", "GoogleTV0001.home", "TV")]
    [InlineData("Desconhecido", "EPSON000001.home", "Impressora")]
    [InlineData("Desconhecido", "iPhone.home", "Apple")]
    [InlineData("Desconhecido", "Galaxy-S23.home", "Telemóvel")]
    [InlineData("Router/Gateway", "OperatorRouter.home", "Router")]
    [InlineData("Desconhecido", "PS5-123.home", "Consola")]
    [InlineData("Desconhecido", "", "Dispositivo")]
    [InlineData("Desconhecido", "laptop-exemplo", "Computador")]
    public void Device_type_uses_hostname_hints(string vendor, string host, string expected) =>
        Assert.Equal(expected, VendorService.GetDeviceType(vendor, host));
}
