using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fo.Fo;

public class FoParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public FoParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.fo", "fo", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.fo", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.fo/fo/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.fo", "fo", "found", "nic.fo.txt");
        var response = parser.Parse("whois.nic.fo", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("nic.fo", response.DomainName.ToString());

        Assert.Equal(new DateTime(2026, 02, 12, 16, 03, 54, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 06, 03, 02, 34, 05, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2028, 01, 03, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant.RegistryId);
        Assert.Equal("FO-umsitingin", response.Registrant.Name);
        Assert.Null(response.Registrant.Created);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Undir Kongavarða 96", response.Registrant.Address[0]);
        Assert.Equal("165", response.Registrant.Address[1]);
        Assert.Equal("FO", response.Registrant.Address[2]);
        Assert.Equal("165", response.Registrant.Address[3]);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact.RegistryId);
        Assert.Equal("FO-umsitingin", response.TechnicalContact.Name);
        Assert.Null(response.TechnicalContact.Created);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Undir Kongavarða 96", response.TechnicalContact.Address[0]);
        Assert.Equal("165", response.TechnicalContact.Address[1]);
        Assert.Equal("FO", response.TechnicalContact.Address[2]);
        Assert.Equal("165", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("xn--gurun-jta.nic.fo", response.NameServers[0]);
        Assert.Equal("mimi.nic.fo", response.NameServers[1]);
        Assert.Equal("a.nic.fo", response.NameServers[2]);
        Assert.Equal("b.nic.fo", response.NameServers[3]);
        Assert.Equal("c.nic.fo", response.NameServers[4]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("serverRenewProhibited", response.DomainStatus[0]);

        Assert.Equal(39, response.FieldsParsed);
    }
}
