using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Register.Si.Si;

public class SiParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SiParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.register.si", "si", "not-found", "not_found.txt");
        var response = parser.Parse("whois.register.si", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.register.si/si/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.register.si", "si", "found", "google.si.txt");
        var response = parser.Parse("whois.register.si", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        AssertWriter.Write(response);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.register.si/si/found/01", response.TemplateName);

        Assert.Equal("google.si", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Markmonitor Inc.", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2005, 04, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 07, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("G830057", response.Registrant.RegistryId);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("client_delete_prohibited,client_update_prohibited", response.DomainStatus[0]);

        Assert.Equal(12, response.FieldsParsed);
    }
}
