using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ai.Ai;

public class AiParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AiParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ai", "ai", "not-found", "u34jedzcq.ai.txt");
        var response = parser.Parse("whois.nic.ai", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/03", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ai", "ai", "found", "google.ai.txt");
        var response = parser.Parse("whois.nic.ai", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.ai", response.DomainName.ToString());

        // Registrant Details
        Assert.Equal("Google LLC", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("Google LLC", response.AdminContact.Organization);
        Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
        Assert.Equal("Google LLC", response.TechnicalContact.Organization);
        Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
        Assert.Equal("CA", response.TechnicalContact.Address[2]);
        Assert.Equal("94043", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns2.zdns.google", response.NameServers[0]);
        Assert.Equal("ns3.zdns.google", response.NameServers[1]);
        Assert.Equal("ns4.zdns.google", response.NameServers[2]);
        Assert.Equal("ns1.zdns.google", response.NameServers[3]);

        Assert.Equal(53, response.FieldsParsed);
    }
}
