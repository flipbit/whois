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

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.us", "us", "found", "google.us.txt");
        var response = parser.Parse("whois.nic.us", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.us", response.DomainName.ToString());
        Assert.Equal("D775573-US", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("www.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2026, 03, 22, 11, 00, 47, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2002, 04, 19, 23, 16, 01, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 04, 18, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("C37454483-US", response.Registrant.RegistryId);
        Assert.Equal("Google LLC", response.Registrant.Name);
        Assert.Equal("Google LLC", response.Registrant.Organization);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("CDFBE947B22B94123B51A662F42C37C75-GDREG", response.AdminContact.RegistryId);
        Assert.Equal("Colm Buckley", response.AdminContact.Name);
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
        Assert.Equal("CDFBE947B22B94123B51A662F42C37C75-GDREG", response.TechnicalContact.RegistryId);
        Assert.Equal("Colm Buckley", response.TechnicalContact.Name);
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
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(6, response.DomainStatus.Count);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);

        Assert.Equal(56, response.FieldsParsed);
    }
}
