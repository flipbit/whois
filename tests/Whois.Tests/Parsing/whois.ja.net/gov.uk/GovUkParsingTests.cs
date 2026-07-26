using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ja.Net.GovUk;

public class GovUkParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GovUkParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.ja.net", "gov.uk", "not-found", "u34jedzcq.gov.uk.txt");
        var response = parser.Parse("whois.ja.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.ja.net/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.gov.uk", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.ja.net", "gov.uk", "found", "found.txt");
        var response = parser.Parse("whois.ja.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.ja.net/found/01", response.TemplateName);

        Assert.Equal("direct.gov.uk", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("NTT Europe Online Ltd", response.Registrar.Name);

        Assert.Equal(new DateTime(2010, 01, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 03, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Directgov", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("Directgov Director", response.AdminContact.Name);
        Assert.Equal("+44 207 261 8723", response.AdminContact.TelephoneNumber);
        Assert.Equal("+44 207 261 8696", response.AdminContact.FaxNumber);
        Assert.Equal("helpdesk@directgov.gsi.gov.uk", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Hercules House", response.AdminContact.Address[0]);
        Assert.Equal("Hercules Road", response.AdminContact.Address[1]);
        Assert.Equal("London", response.AdminContact.Address[2]);
        Assert.Equal("SE1 7DU", response.AdminContact.Address[3]);
        Assert.Equal("United Kingdom", response.AdminContact.Address[4]);


        // Nameservers
        Assert.Equal(8, response.NameServers.Count);
        Assert.Equal("eur5.akam.net", response.NameServers[0]);
        Assert.Equal("eur6.akam.net", response.NameServers[1]);
        Assert.Equal("ns1-173.akam.net", response.NameServers[2]);
        Assert.Equal("ns1-31.akam.net", response.NameServers[3]);
        Assert.Equal("usc4.akam.net", response.NameServers[4]);
        Assert.Equal("use10.akam.net", response.NameServers[5]);
        Assert.Equal("usw2.akam.net", response.NameServers[6]);
        Assert.Equal("usw4.akam.net", response.NameServers[7]);

        Assert.Equal(24, response.FieldsParsed);
    }
}
