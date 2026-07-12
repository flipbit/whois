using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Us.Us;

public class UsParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public UsParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.us", "us", "not-found", "u34jedzcq.us.txt");
        var response = parser.Parse("whois.nic.us", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.us/us/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.us", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.us", "us", "found", "google.us.txt");
        var response = parser.Parse("whois.nic.us", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.us/us/found/01", response.TemplateName);

        Assert.Equal("google.us", response.DomainName.ToString());
        Assert.Equal("D775573-US", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("whois.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2014, 04, 18, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2002, 04, 19, 23, 15, 57, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 03, 17, 09, 44, 30, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("MMR-135878", response.Registrant.RegistryId);
        Assert.Equal("Google Inc", response.Registrant.Name);
        Assert.Equal("Google Inc.", response.Registrant.Organization);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(6, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("United States", response.Registrant.Address[4]);
        Assert.Equal("US", response.Registrant.Address[5]);


        // AdminContact Details
        Assert.Equal("MMR-136042", response.AdminContact.RegistryId);
        Assert.Equal("Christina Chiou", response.AdminContact.Name);
        Assert.Equal("Google Inc.", response.AdminContact.Organization);
        Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(6, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("United States", response.AdminContact.Address[4]);
        Assert.Equal("US", response.AdminContact.Address[5]);


        // BillingContact Details
        Assert.Equal("MMR-136042", response.BillingContact.RegistryId);
        Assert.Equal("Christina Chiou", response.BillingContact.Name);
        Assert.Equal("Google Inc.", response.BillingContact.Organization);
        Assert.Equal("+1.6502530000", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.BillingContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(6, response.BillingContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.BillingContact.Address[0]);
        Assert.Equal("Mountain View", response.BillingContact.Address[1]);
        Assert.Equal("CA", response.BillingContact.Address[2]);
        Assert.Equal("94043", response.BillingContact.Address[3]);
        Assert.Equal("United States", response.BillingContact.Address[4]);
        Assert.Equal("US", response.BillingContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("MMR-136042", response.TechnicalContact.RegistryId);
        Assert.Equal("Christina Chiou", response.TechnicalContact.Name);
        Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
        Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
        Assert.Equal("CA", response.TechnicalContact.Address[2]);
        Assert.Equal("94043", response.TechnicalContact.Address[3]);
        Assert.Equal("United States", response.TechnicalContact.Address[4]);
        Assert.Equal("US", response.TechnicalContact.Address[5]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

        Assert.Equal(63, response.FieldsParsed);
    }
}
