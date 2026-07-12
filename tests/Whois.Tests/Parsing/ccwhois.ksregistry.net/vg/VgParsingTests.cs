using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Ccwhois.Ksregistry.Net.Vg;

public class VgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public VgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("ccwhois.ksregistry.net", "vg", "not-found", "not_found.txt");
        var response = parser.Parse("ccwhois.ksregistry.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("ccwhois.ksregistry.net", "vg", "found", "google.vg.txt");
        var response = parser.Parse("ccwhois.ksregistry.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);
        Assert.Equal("google.vg", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 3, 1, 0, 2, 14), response.Updated);
        Assert.Equal(new DateTime(1999, 6, 5, 0, 0, 0), response.Registered);
        Assert.Equal(new DateTime(2013, 6, 5, 0, 0, 0), response.Expiration);
        Assert.Equal("P-GFI26", response.Registrant.RegistryId);
        Assert.Equal("Google, Inc.", response.Registrant.Name);
        Assert.Equal("Google, Inc.", response.Registrant.Organization);

        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("94043", response.Registrant.Address[2]);
        Assert.Equal("US", response.Registrant.Address[3]);

        Assert.Equal("+1.6503300100", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6506181499", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        Assert.Equal("P-GFI26", response.AdminContact.RegistryId);
        Assert.Equal("Google, Inc.", response.AdminContact.Name);
        Assert.Equal("Google, Inc.", response.AdminContact.Organization);

        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("94043", response.AdminContact.Address[2]);
        Assert.Equal("US", response.AdminContact.Address[3]);

        Assert.Equal("+1.6503300100", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.6506181499", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        Assert.Equal("P-UDM24", response.BillingContact.RegistryId);
        Assert.Equal("UNKNOWN MarkMonitor", response.BillingContact.Name);
        Assert.Equal("MarkMonitor", response.BillingContact.Organization);

        Assert.Equal(4, response.BillingContact.Address.Count);
        Assert.Equal("391 North Ancestor Place", response.BillingContact.Address[0]);
        Assert.Equal("ID", response.BillingContact.Address[1]);
        Assert.Equal("83704", response.BillingContact.Address[2]);
        Assert.Equal("US", response.BillingContact.Address[3]);

        Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.2083895799", response.BillingContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

        Assert.Equal("P-GFI26", response.TechnicalContact.RegistryId);
        Assert.Equal("Google, Inc.", response.TechnicalContact.Name);
        Assert.Equal("Google, Inc.", response.TechnicalContact.Organization);

        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
        Assert.Equal("94043", response.TechnicalContact.Address[2]);
        Assert.Equal("US", response.TechnicalContact.Address[3]);

        Assert.Equal("+1.6503300100", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.6506181499", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);
    }
}
