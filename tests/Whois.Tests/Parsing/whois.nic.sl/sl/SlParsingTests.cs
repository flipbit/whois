using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sl.Sl;

public class SlParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SlParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.sl", "sl", "not-found", "u34jedzcq.sl.txt");
        var response = parser.Parse("whois.nic.sl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.sl", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.sl", "sl", "found", "google.sl.txt");
        var response = parser.Parse("whois.nic.sl", sample);

        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.sl", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("nicsl", response.Registrar.Name);

        Assert.Equal(new DateTime(2008, 05, 17, 21, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 05, 17, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("Google LLC", response.Registrant.Organization);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.Registrant.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Null(response.AdminContact.RegistryId);
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("Markmonitor Inc.", response.AdminContact.Organization);
        Assert.Equal("+1.2083895740", response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1120 S. Rackham Way", response.AdminContact.Address[0]);
        Assert.Equal("Meridian", response.AdminContact.Address[1]);
        Assert.Equal("ID", response.AdminContact.Address[2]);
        Assert.Equal("83642", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
        Assert.Equal("Markmonitor Inc.", response.TechnicalContact.Organization);
        Assert.Equal("+1.2083895740", response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("1120 S. Rackham Way", response.TechnicalContact.Address[0]);
        Assert.Equal("Meridian", response.TechnicalContact.Address[1]);
        Assert.Equal("ID", response.TechnicalContact.Address[2]);
        Assert.Equal("83642", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(48, response.FieldsParsed);
    }
}
