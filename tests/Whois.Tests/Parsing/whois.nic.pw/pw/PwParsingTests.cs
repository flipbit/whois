using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Pw.Pw;

public class PwParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public PwParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.pw", "pw", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.pw", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.pw", "pw", "found", "google.pw.txt");
        var response = parser.Parse("whois.nic.pw", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.pw", response.DomainName.ToString());
        Assert.Equal("CNIC-DO949924", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2014, 01, 18, 00, 13, 36, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2012, 10, 12, 10, 19, 46, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2017, 02, 10, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("H2396041", response.Registrant.RegistryId);
        Assert.Equal("DNS Admin - Google Inc", response.Registrant.Name);
        Assert.Equal("Google Inc", response.Registrant.Organization);
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
        Assert.Equal("H2396041", response.AdminContact.RegistryId);
        Assert.Equal("DNS Admin - Google Inc", response.AdminContact.Name);
        Assert.Equal("Google Inc", response.AdminContact.Organization);
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
        Assert.Equal("7061-EM", response.BillingContact.RegistryId);
        Assert.Equal("Domain Administrator", response.BillingContact.Name);
        Assert.Equal("MarkMonitor, Inc.", response.BillingContact.Organization);
        Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(6, response.BillingContact.Address.Count);
        Assert.Equal("Emerald Tech Center", response.BillingContact.Address[0]);
        Assert.Equal("391 N. Ancestor Place", response.BillingContact.Address[1]);
        Assert.Equal("Boise", response.BillingContact.Address[2]);
        Assert.Equal("ID", response.BillingContact.Address[3]);
        Assert.Equal("83704", response.BillingContact.Address[4]);
        Assert.Equal("US", response.BillingContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("H2396041", response.TechnicalContact.RegistryId);
        Assert.Equal("DNS Admin - Google Inc", response.TechnicalContact.Name);
        Assert.Equal("Google Inc", response.TechnicalContact.Organization);
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
        Assert.Equal(7, response.NameServers.Count);
        Assert.Equal("ns1.markmonitor.com", response.NameServers[0]);
        Assert.Equal("ns2.markmonitor.com", response.NameServers[1]);
        Assert.Equal("ns3.markmonitor.com", response.NameServers[2]);
        Assert.Equal("ns4.markmonitor.com", response.NameServers[3]);
        Assert.Equal("ns5.markmonitor.com", response.NameServers[4]);
        Assert.Equal("ns6.markmonitor.com", response.NameServers[5]);
        Assert.Equal("ns7.markmonitor.com", response.NameServers[6]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[2]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[3]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(65, response.FieldsParsed);
    }
}
