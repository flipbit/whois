using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.XnFzc2c9e2c;

public class XnFzc2c9e2cParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public XnFzc2c9e2cParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.lk", "xn--fzc2c9e2c", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.Equal(WhoisStatus.Unknown, response.Status);
        Assert.Equal(0, response.ContentLength);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.lk", "xn--fzc2c9e2c", "found", "xn--fzc3a2azd8dsa2ktat.xn--fzc2c9e2c.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lk/found/02", response.TemplateName);

        Assert.Equal("xn--fzc3a2azd8dsa2ktat.xn--fzc2c9e2c", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Nameservers
        Assert.Equal(1, response.NameServers.Count);
        Assert.Equal("ns3.pipedns.com.", response.NameServers[0]);

        Assert.Equal(5, response.FieldsParsed);
    }
}
