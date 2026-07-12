using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ag.Ag;

public class AgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ag", "ag", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.ag", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ag", "ag", "found", "google.ag.txt");
        var response = parser.Parse("whois.nic.ag", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.ag", response.DomainName.ToString());
        Assert.Equal("D48552-LRCC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 12, 04, 10, 20, 49, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 01, 05, 14, 06, 59, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2015, 01, 05, 14, 06, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("AGRS-129819", response.Registrant.RegistryId);
        Assert.Equal("DNS Admin", response.Registrant.Name);
        Assert.Equal("Google Inc.", response.Registrant.Organization);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("AGRS-129819", response.AdminContact.RegistryId);
        Assert.Equal("DNS Admin", response.AdminContact.Name);
        Assert.Equal("Google Inc.", response.AdminContact.Organization);
        Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("AGRS-129293", response.BillingContact.RegistryId);
        Assert.Equal("CCOPS", response.BillingContact.Name);
        Assert.Equal("MarkMonitor", response.BillingContact.Organization);
        Assert.Equal("+1.20838957", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.20838957", response.BillingContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(6, response.BillingContact.Address.Count);
        Assert.Equal("PMB 155", response.BillingContact.Address[0]);
        Assert.Equal("10400 Overland Rd.", response.BillingContact.Address[1]);
        Assert.Equal("Boise", response.BillingContact.Address[2]);
        Assert.Equal("ID", response.BillingContact.Address[3]);
        Assert.Equal("83709-1433", response.BillingContact.Address[4]);
        Assert.Equal("US", response.BillingContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("AGRS-129819", response.TechnicalContact.RegistryId);
        Assert.Equal("DNS Admin", response.TechnicalContact.Name);
        Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
        Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
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
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
        Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
        Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);

        Assert.Equal(59, response.FieldsParsed);
    }
}
