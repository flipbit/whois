using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Biz.Biz;

public class BizParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public BizParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.biz", "biz", "not-found", "not_found.txt");
        var response = parser.Parse("whois.biz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(1, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.biz/biz/not-found/01", response.TemplateName);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.biz", "biz", "found", "google.biz.txt");
        var response = parser.Parse("whois.biz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.biz", response.DomainName.ToString());
        Assert.Equal("REDACTED FOR PRIVACY", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor, Inc.", response.Registrar.Name);
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("registry.admin@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);
        Assert.Equal("www.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2026, 02, 27, 10, 34, 33, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2002, 03, 27, 16, 03, 44, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 03, 26, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);
        Assert.Equal("Google LLC", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(36, response.FieldsParsed);
    }
}
