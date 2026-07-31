using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ly.Ly;

public class LyParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public LyParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ly", "ly", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.ly", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ly/ly/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ly", "ly", "found", "found.txt");
        var response = parser.Parse("whois.nic.ly", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ly/ly/found/01", response.TemplateName);


        Assert.Equal(new DateTime(2009, 08, 07, 22, 52, 02, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2007, 10, 03, 13, 36, 48, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 10, 03, 13, 36, 48, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("DNS Admin", response.Registrant.Name);
        Assert.Equal("Google Inc.", response.Registrant.Organization);
        Assert.Equal("+16503300100", response.Registrant.TelephoneNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("United States of America", response.Registrant.Address[3]);
        Assert.Equal("94043", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("DNS Admin", response.AdminContact.Name);
        Assert.Equal("Google Inc.", response.AdminContact.Organization);
        Assert.Equal("+16503300100", response.AdminContact.TelephoneNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("US", response.AdminContact.Address[3]);
        Assert.Equal("94043", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("Domain Administrator", response.BillingContact.Name);
        Assert.Equal("MarkMonitor", response.BillingContact.Organization);
        Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.2083895799", response.BillingContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("10400 Overland Rd\\r\\nPMB 155", response.BillingContact.Address[0]);
        Assert.Equal("Boise", response.BillingContact.Address[1]);
        Assert.Equal("ID", response.BillingContact.Address[2]);
        Assert.Equal("US", response.BillingContact.Address[3]);
        Assert.Equal("83709", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("Domain Admin", response.TechnicalContact.Name);
        Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);
        Assert.Equal("+1.2083895740", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.2083895799", response.TechnicalContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("10400 Overland Rd\\r\\nPMB 155", response.TechnicalContact.Address[0]);
        Assert.Equal("Boise", response.TechnicalContact.Address[1]);
        Assert.Equal("ID", response.TechnicalContact.Address[2]);
        Assert.Equal("US", response.TechnicalContact.Address[3]);
        Assert.Equal("83709", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns2.google.com", response.NameServers[0]);
        Assert.Equal("ns1.google.com", response.NameServers[1]);
        Assert.Equal("ns4.google.com", response.NameServers[2]);
        Assert.Equal("ns3.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVE", response.DomainStatus[0]);

        Assert.Equal(47, response.FieldsParsed);
    }
}
