using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lv.Lv;

public class LvParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public LvParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.lv", "lv", "not-found", "u34jedzcq.lv.txt");
        var response = parser.Parse("whois.nic.lv", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lv/lv/found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.lv", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("free", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.lv", "lv", "found", "google.lv.txt");
        var response = parser.Parse("whois.nic.lv", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lv/lv/found/01", response.TemplateName);

        Assert.Equal("google.lv", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Null(response.Registrar.AbuseEmail);
        Assert.Null(response.Registrar.AbuseTelephoneNumber);


        // Registrant Details
        Assert.Equal("Google LLC", response.Registrant.Name);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway, Mountain View, CA, 94043, USA", response.Registrant.Address[0]);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal(10, response.FieldsParsed);
    }
}
