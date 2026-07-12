using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Im.Im;

public class ImParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ImParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.im", "im", "not-found", "u34jedzcq.im.txt");
        var response = parser.Parse("whois.nic.im", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.im/im/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.im", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.im", "im", "found", "google.im.txt");
        var response = parser.Parse("whois.nic.im", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.im/im/found/01", response.TemplateName);

        Assert.Equal("google.im", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Redacted", response.Registrar.Name);

        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Equal("Redacted", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Address", response.Registrant.Address[0]);
        Assert.Equal("Redacted", response.Registrant.Address[1]);
        Assert.Equal("Name: Redacted", response.Registrant.Address[2]);
        Assert.Equal("Address", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(8, response.FieldsParsed);
    }
}
