using Xunit;

namespace Whois.IpAddresses;

public class WhoisIpTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("2.0.0.1")]
    [Trait("Category", "Integration")]
    public async Task WhoisIpLookup_ReturnsResult(string ipStr)
    {
        var lookup = new WhoisLookup();
        var request = new IpRequest(ipStr)
        {
            PreferredProtocol = ProtocolPreference.Whois,
        };

        var result = await lookup.Lookup(request);

        Assert.Equal(LookupProtocol.Whois, result.Protocol);
        Assert.NotEmpty(result.RawContent);
    }
}
