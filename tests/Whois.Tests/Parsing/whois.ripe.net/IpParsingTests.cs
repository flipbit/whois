using Whois.Parsers;
using Whois.Protocols;
using Xunit;

namespace Whois.Parsing.Whois.Ripe.Net.Ip;

public class IpParsingTests : ParsingTests
{
    private readonly WhoisParser _parser;

    public IpParsingTests()
    {
        _parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.ripe.net", "ip", "found", "found.txt");
        var response = _parser.Parse<IpRecord>("whois.ripe.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);
        Assert.NotNull(response.Network);
        Assert.NotNull(response.NetName);
        Assert.True(response.FieldsParsed > 0);
    }
}
