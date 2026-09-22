using Xunit;

namespace Whois.IpAddresses;

public class RdapIpTests
{
    [Theory]
    [InlineData("8.8.8.8", "ARIN")]
    [InlineData("2.0.0.1", "RIPE")]
    [InlineData("1.1.1.1", "APNIC")]
    [InlineData("200.0.0.1", "LACNIC")]
    [InlineData("196.0.0.1", "AFRINIC")]
    [Trait("Category", "Integration")]
    public async Task RdapIpLookup_IPv4(string ipStr, string rirHint)
    {
        var lookup = new WhoisLookup();
        var request = new IpRequest(ipStr)
        {
            PreferredProtocol = ProtocolPreference.Rdap,
        };

        var result = await lookup.Lookup(request);

        Assert.Equal(LookupProtocol.Rdap, result.Protocol);
        Assert.Equal(RegistrationStatus.Found, result.Response.Status);
        Assert.NotNull(result.Response.Network);
        Assert.NotNull(result.Response.NetName);
        Assert.NotNull(result.Response.Country);
        Assert.NotEmpty(result.RawContent);

        _ = rirHint; // used as test case label
    }

    [Theory]
    [InlineData("2001:4860:4860::8888", "ARIN")]
    [InlineData("2a00:1450:4001::1", "RIPE")]
    [InlineData("2400:cb00:2048::1", "APNIC")]
    [InlineData("2800:3f0:4001::1", "LACNIC")]
    [InlineData("2c0f:f248::1", "AFRINIC")]
    [Trait("Category", "Integration")]
    public async Task RdapIpLookup_IPv6(string ipStr, string rirHint)
    {
        var lookup = new WhoisLookup();
        var request = new IpRequest(ipStr)
        {
            PreferredProtocol = ProtocolPreference.Rdap,
        };

        var result = await lookup.Lookup(request);

        Assert.Equal(LookupProtocol.Rdap, result.Protocol);
        Assert.Equal(RegistrationStatus.Found, result.Response.Status);
        Assert.NotNull(result.Response.Network);
        Assert.NotEmpty(result.RawContent);

        _ = rirHint; // used as test case label
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task Query_AutoDetectsIp()
    {
        var lookup = new WhoisLookup();
        var result = await lookup.Query("8.8.8.8");

        Assert.IsType<IpInfo>(result.Response);
        Assert.Equal(RegistrationStatus.Found, result.Response.Status);
    }
}
