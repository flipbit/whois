using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Mn;

public class MnParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MnParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.afilias-grs.info", "mn", "not-found", "not_found.txt");
        var response = parser.Parse("whois.afilias-grs.info", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(1, response.FieldsParsed);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.afilias-grs.info", "mn", "found", "found.txt");
        var response = parser.Parse("whois.afilias-grs.info", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.mn", response.DomainName.ToString());
        Assert.Equal("D444956-LRCC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 03, 06, 10, 21, 48, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 04, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 04, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("MNM-11332", response.Registrant.RegistryId);
        Assert.Equal("DNS Admin", response.Registrant.Name);
        Assert.Equal("Google Inc.", response.Registrant.Organization);
        Assert.Equal("+165.03300100", response.Registrant.TelephoneNumber);
        Assert.Equal("+165.06188571", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("MNM-11332", response.AdminContact.RegistryId);
        Assert.Equal("DNS Admin", response.AdminContact.Name);
        Assert.Equal("Google Inc.", response.AdminContact.Organization);
        Assert.Equal("+165.03300100", response.AdminContact.TelephoneNumber);
        Assert.Equal("+165.06188571", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("mmr-33293", response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Admin", response.TechnicalContact.Name);
        Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);
        Assert.Equal("+1.2083895740", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.2083895771", response.TechnicalContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("391 N. Ancestor Place", response.TechnicalContact.Address[0]);
        Assert.Equal("Suite 150", response.TechnicalContact.Address[1]);
        Assert.Equal("Boise", response.TechnicalContact.Address[2]);
        Assert.Equal("CA", response.TechnicalContact.Address[3]);
        Assert.Equal("83704", response.TechnicalContact.Address[4]);
        Assert.Equal("US", response.TechnicalContact.Address[5]);


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

        Assert.Equal(48, response.FieldsParsed);
    }
}
