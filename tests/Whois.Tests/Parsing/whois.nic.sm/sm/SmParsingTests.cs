using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sm.Sm;

public class SmParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SmParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.sm", "sm", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.sm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.sm/sm/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.sm", "sm", "found", "google.sm.txt");
        var response = parser.Parse("whois.nic.sm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.sm/sm/found/01", response.TemplateName);

        Assert.Equal("google.sm", response.DomainName.ToString());

        Assert.Equal(new DateTime(2008, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);

        // Registrant Details
        Assert.Equal("Rose Hagan", response.Registrant.Name);
        Assert.Equal("Google, Inc.", response.Registrant.Organization);
        Assert.Equal("+1 650 2530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1 650 6188571", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("US 94043 Mountain View (CA)", response.Registrant.Address[1]);
        Assert.Equal("US", response.Registrant.Address[2]);


        // TechnicalContact Details
        Assert.Equal("Domain Names Department", response.TechnicalContact.Name);
        Assert.Equal("Visiant Outsourcing S.r.l.", response.TechnicalContact.Organization);
        Assert.Equal("+39 011 3473520", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+39 011 3473522", response.TechnicalContact.FaxNumber);
        Assert.Equal("domains.outsourcing@visiant.it", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Strada del Drosso 128/6", response.TechnicalContact.Address[0]);
        Assert.Equal("I 10135 Torino (TO)", response.TechnicalContact.Address[1]);
        Assert.Equal("IT", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(24, response.FieldsParsed);
    }
}
