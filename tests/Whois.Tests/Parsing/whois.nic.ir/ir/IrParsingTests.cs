using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ir.Ir;

public class IrParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public IrParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ir", "ir", "not-found", "u34jedzcq.ir.txt");
        var response = parser.Parse("whois.nic.ir", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ir/ir/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ir", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ir", "ir", "found", "google.ir.txt");
        var response = parser.Parse("whois.nic.ir", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ir/ir/found/01", response.TemplateName);

        Assert.Equal("google.ir", response.DomainName.ToString());

        Assert.Null(response.Updated);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.googledomains.com", response.NameServers[0]);
        Assert.Equal("ns2.googledomains.com", response.NameServers[1]);
        Assert.Equal("ns3.googledomains.com", response.NameServers[2]);
        Assert.Equal("ns4.googledomains.com", response.NameServers[3]);

        Assert.Equal(6, response.FieldsParsed);
    }
}
