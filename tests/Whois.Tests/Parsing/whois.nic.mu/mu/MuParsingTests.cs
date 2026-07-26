using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Mu.Mu;

public class MuParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MuParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.mu", "mu", "not-found", "u34jedzcq.mu.txt");
        var response = parser.Parse("whois.nic.mu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.mu", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.mu", "mu", "found", "google.mu.txt");
        var response = parser.Parse("whois.nic.mu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.mu", response.DomainName.ToString());
        Assert.Equal("70557-CoCCA", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2013, 11, 17, 10, 20, 08, 489, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2000, 12, 20, 13, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 12, 19, 13, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("177502-CoCCA", response.Registrant.RegistryId);
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
        Assert.Equal("177502-CoCCA", response.AdminContact.RegistryId);
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


        // TechnicalContact Details
        Assert.Equal("177502-CoCCA", response.TechnicalContact.RegistryId);
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
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);
        Assert.Equal("ok", response.DomainStatus[2]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[3]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(49, response.FieldsParsed);
    }
}
