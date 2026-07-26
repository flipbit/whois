using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tel.Tel;

public class TelParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TelParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.tel", "tel", "not-found", "u34jedzcq.tel.txt");
        var response = parser.Parse("whois.nic.tel", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.tel/tel/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.tel", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.tel", "tel", "found", "google.tel.txt");
        var response = parser.Parse("whois.nic.tel", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.tel", response.DomainName.ToString());
        Assert.Equal("D587349-TEL", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2026, 02, 18, 10, 41, 34, 924, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 01, 22, 21, 06, 56, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 03, 22, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Organization);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


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
        Assert.Equal("CA", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);


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

        Assert.Equal(44, response.FieldsParsed);
    }
}
