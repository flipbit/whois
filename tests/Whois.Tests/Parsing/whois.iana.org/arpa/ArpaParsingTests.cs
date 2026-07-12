using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iana.Org.Arpa;

public class ArpaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ArpaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.iana.org", "arpa", "not-found", "not_found.txt");
        var response = parser.Parse("whois.iana.org", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iana.org/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.arpa", response.DomainName.ToString());


        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.iana.org", "arpa", "found", "found.txt");
        var response = parser.Parse("whois.iana.org", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iana.org/found/02", response.TemplateName);

        Assert.Equal("ip6.arpa", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 07, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 11, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Internet Assigned Numbers Authority (IANA)", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("4676 Admiralty Way", response.Registrant.Address[0]);
        Assert.Equal("Suite 330", response.Registrant.Address[1]);
        Assert.Equal("Marina del Rey California 90292-6610", response.Registrant.Address[2]);
        Assert.Equal("US", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("Internet Architecture Board (IAB)", response.AdminContact.Organization);
        Assert.Equal("+1 703 326 9880", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1 703 326 9881", response.AdminContact.FaxNumber);
        Assert.Equal("iab@iab.org", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("1775 Wiehle Ave.", response.AdminContact.Address[0]);
        Assert.Equal("Suite 102", response.AdminContact.Address[1]);
        Assert.Equal("Reston Virginia 20190-5108", response.AdminContact.Address[2]);
        Assert.Equal("United States", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("Internet Assigned Numbers Authority (IANA)", response.TechnicalContact.Organization);
        Assert.Equal("+1 310 823 9358", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1 310 823 8649", response.TechnicalContact.FaxNumber);
        Assert.Equal("iana@iana.org", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("4676 Admiralty Way", response.TechnicalContact.Address[0]);
        Assert.Equal("Suite 330", response.TechnicalContact.Address[1]);
        Assert.Equal("Marina del Rey California 90292-6610", response.TechnicalContact.Address[2]);
        Assert.Equal("United States", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("a.ip6-servers.arpa", response.NameServers[0]);
        Assert.Equal("b.ip6-servers.arpa", response.NameServers[1]);
        Assert.Equal("c.ip6-servers.arpa", response.NameServers[2]);
        Assert.Equal("d.ip6-servers.arpa", response.NameServers[3]);
        Assert.Equal("e.ip6-servers.arpa", response.NameServers[4]);
        Assert.Equal("f.ip6-servers.arpa", response.NameServers[5]);

        Assert.Equal(31, response.FieldsParsed);
    }
}
