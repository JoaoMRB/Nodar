using Nodar.Core.Services.Vulnerabilities;

namespace Nodar.Tests;

public class VersionComparerTests
{
    [Theory]
    [InlineData("2.4.58", "2.4.58", 0)]
    [InlineData("2.4.9", "2.4.10", -1)]      // numérico, não alfabético
    [InlineData("2.4.10", "2.4.9", 1)]
    [InlineData("1.0", "1.0.0", -1)]
    [InlineData("8.2", "8.2p1", -1)]         // sufixo de patch OpenSSH é posterior
    [InlineData("9.8p1", "9.8", 1)]
    [InlineData("9.7p1", "9.8", -1)]
    [InlineData("8.2p1", "8.2p2", -1)]
    [InlineData("1.3.5", "1.3.5e", -1)]      // letras de patch ProFTPD
    [InlineData("1.3.5a", "1.3.5e", -1)]
    [InlineData("1.0rc1", "1.0", -1)]        // pré-lançamento é anterior
    [InlineData("1.0-beta2", "1.0", -1)]
    [InlineData("1.0b2", "1.0", -1)]
    [InlineData("1.0alpha", "1.0beta", -1)]
    [InlineData("2022.83", "2024.85", -1)]   // Dropbear
    [InlineData("10.0", "8.5", 1)]
    [InlineData("007", "7", 0)]
    [InlineData("99999999999999999999", "1", 1)] // sem overflow
    public void Compare_orders_real_world_versions(string left, string right, int expected)
    {
        Assert.Equal(expected, Math.Sign(VersionComparer.Compare(left, right)));
        Assert.Equal(-expected, Math.Sign(VersionComparer.Compare(right, left)));
    }

    [Theory]
    [InlineData("8.2p1", "8.2")]
    [InlineData("1.3.5e", "1.3.5")]
    [InlineData("10.6.12", "10.6.12")]
    [InlineData("abc", "")]
    public void GetNumericBase_strips_suffix(string version, string expected) =>
        Assert.Equal(expected, VersionComparer.GetNumericBase(version));
}
