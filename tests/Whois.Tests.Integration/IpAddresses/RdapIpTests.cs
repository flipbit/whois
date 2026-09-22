using System.Net;
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
    public async Task RdapIpLookup_ReturnsResult(string ipStr, string expectedRirHint)
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

        _ = expectedRirHint; // used as test case label via InlineData
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task RdapIpLookup_IPv6()
    {
        var lookup = new WhoisLookup();
        var result = await lookup.Lookup(IPAddress.Parse("2001:4860:4860::8888"));

        Assert.Equal(RegistrationStatus.Found, result.Response.Status);
        Assert.NotNull(result.Response.Network);
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
