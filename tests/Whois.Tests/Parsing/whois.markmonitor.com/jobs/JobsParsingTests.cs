using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Markmonitor.Com.Jobs;

public class JobsParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public JobsParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.markmonitor.com", "jobs", "found", "found.txt");
        var response = parser.Parse("whois.markmonitor.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.jobs", response.DomainName.ToString());
        Assert.Equal("86932313_DOMAIN_JOBS-VRSN", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor, Inc.", response.Registrar.Name);
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
        Assert.Equal("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2017, 07, 27, 20, 59, 01, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 09, 15, 07, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2017, 09, 15, 04, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("MMR-168840", response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("Google Inc.", response.Registrant.Organization);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway,", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("MMR-168840", response.AdminContact.RegistryId);
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("Google Inc.", response.AdminContact.Organization);
        Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway,", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("MMR-168840", response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
        Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
        Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway,", response.TechnicalContact.Address[0]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
        Assert.Equal("CA", response.TechnicalContact.Address[2]);
        Assert.Equal("94043", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[2]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(51, response.FieldsParsed);
    }
}
