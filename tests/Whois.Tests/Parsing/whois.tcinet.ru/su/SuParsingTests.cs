using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tcinet.Ru.Su;

public class SuParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SuParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.tcinet.ru", "su", "not-found", "not_found.txt");
        var response = parser.Parse("whois.tcinet.ru", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.tcinet.ru/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.tcinet.ru", "su", "found", "found.txt");
        var response = parser.Parse("whois.tcinet.ru", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.tcinet.ru/found/01", response.TemplateName);

        Assert.Equal("google.su", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("RUCENTER-SU", response.Registrar.Name);

        Assert.Equal(new DateTime(2005, 10, 15, 20, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2021, 10, 15, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("domens@mail.com", response.Registrant.Email);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns3.nic.ru.", response.NameServers[0]);
        Assert.Equal("ns4.nic.ru.", response.NameServers[1]);
        Assert.Equal("ns8.nic.ru.", response.NameServers[2]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("REGISTERED", response.DomainStatus[0]);
        Assert.Equal("DELEGATED", response.DomainStatus[1]);

        Assert.Equal(10, response.FieldsParsed);
    }
}
