using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.At.At;

public class AtParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AtParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.at", "at", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.at", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.at/at/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.at", "at", "found", "google.at.txt");
        var response = parser.Parse("whois.nic.at", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.at/at/found/01", response.TemplateName);

        Assert.Equal("google.at", response.DomainName.ToString());

        Assert.Equal(new DateTime(2024, 11, 13, 19, 36, 02, 000, DateTimeKind.Utc), response.Updated);

        // Registrant Details
        Assert.Equal("GL11783559-NICAT", response.Registrant.RegistryId);

        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Equal("GI7803025-NICAT", response.TechnicalContact.RegistryId);
        Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
        Assert.Equal("+16502530000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+16502530001", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
        Assert.Equal("94043", response.TechnicalContact.Address[1]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[2]);
        Assert.Equal("United States of America (the)", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(39, response.FieldsParsed);
    }
}
