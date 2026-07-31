using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.XnXkc2al3hye2a;

public class XnXkc2al3hye2aParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public XnXkc2al3hye2aParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.lk", "xn--xkc2al3hye2a", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.Equal(RegistrationStatus.Unknown, response.Status);
        Assert.Equal(0, response.ContentLength);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.lk", "xn--xkc2al3hye2a", "found", "found.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lk/found/02", response.TemplateName);

        Assert.Equal("xn--4kcolx4fsa0gdt6j.xn--xkc2al3hye2a", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.pipedns.com.", response.NameServers[0]);
        Assert.Equal("ns2.pipedns.com.", response.NameServers[1]);
        Assert.Equal("ns3.pipedns.com.", response.NameServers[2]);

        Assert.Equal(7, response.FieldsParsed);
    }
}
