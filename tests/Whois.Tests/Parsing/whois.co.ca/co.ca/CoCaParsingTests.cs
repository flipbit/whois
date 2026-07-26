using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Co.Ca.CoCa;

public class CoCaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CoCaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.co.ca", "co.ca", "not-found", "u34jedzcq.co.ca.txt");
        var response = parser.Parse("whois.co.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.co.ca/co.ca/not-found/01", response.TemplateName);

        Assert.Equal("domain", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.co.ca", "co.ca", "found", "found.txt");
        var response = parser.Parse("whois.co.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.co.ca/co.ca/found/01", response.TemplateName);

        Assert.Equal("internet.co.ca", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("RegCA Enterprises Inc. (www.reg.ca)", response.Registrar.Name);

        Assert.Equal(new DateTime(2005, 06, 25, 16, 03, 30, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 06, 25, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.canadawebhosting.com", response.NameServers[0]);
        Assert.Equal("ns2.canadawebhosting.com", response.NameServers[1]);

        Assert.Equal(7, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.co.ca", "co.ca", "reserved", "reserved.txt");
        var response = parser.Parse("whois.co.ca", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.co.ca/co.ca/reserved/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }
}
