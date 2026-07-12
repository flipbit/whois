using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tznic.Or.Tz.Tz;

public class TzParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TzParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_expired()
    {
        var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "expired", "expired.txt");
        var response = parser.Parse("whois.tznic.or.tz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Expired, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.tznic.or.tz/tz/found/01", response.TemplateName);

        Assert.Equal("amanabank.co.tz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("REG-XTREME", response.Registrar.Name);

        Assert.Equal(new DateTime(2012, 04, 24, 18, 53, 54, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2011, 04, 28, 19, 27, 26, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 04, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("AB2-EXTREME", response.Registrant.RegistryId);
        Assert.Equal("Abdul Bandawe", response.Registrant.Name);
        Assert.Equal("Amana Bank Ltd", response.Registrant.Organization);
        Assert.Equal("+255.713509199", response.Registrant.TelephoneNumber);
        Assert.Equal("abdul.bandawe@amanabank.co.tz", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("3rd Floor, PPF Tower", response.Registrant.Address[0]);
        Assert.Equal("P. O. Box 9771", response.Registrant.Address[1]);
        Assert.Equal("Dar es Salaam", response.Registrant.Address[2]);
        Assert.Equal("9771", response.Registrant.Address[3]);
        Assert.Equal("TZ", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("AB2-EXTREME", response.AdminContact.RegistryId);
        Assert.Equal("Abdul Bandawe", response.AdminContact.Name);
        Assert.Equal("Amana Bank Ltd", response.AdminContact.Organization);
        Assert.Equal("+255.713509199", response.AdminContact.TelephoneNumber);
        Assert.Equal("abdul.bandawe@amanabank.co.tz", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("3rd Floor, PPF Tower", response.AdminContact.Address[0]);
        Assert.Equal("P. O. Box 9771", response.AdminContact.Address[1]);
        Assert.Equal("Dar es Salaam", response.AdminContact.Address[2]);
        Assert.Equal("9771", response.AdminContact.Address[3]);
        Assert.Equal("TZ", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("MS1-TZNIC", response.TechnicalContact.RegistryId);
        Assert.Equal("Mohsin Sumar", response.TechnicalContact.Name);
        Assert.Equal("Extreme Web Technologies", response.TechnicalContact.Organization);
        Assert.Equal("+255.784870811", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("info@extremewebtechnologies.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("5th Floor, Osman Towers", response.TechnicalContact.Address[0]);
        Assert.Equal("Zanaki Street", response.TechnicalContact.Address[1]);
        Assert.Equal("Dar es Salaam", response.TechnicalContact.Address[2]);
        Assert.Equal("P.O.Box 14001", response.TechnicalContact.Address[3]);
        Assert.Equal("TZ", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns5.e-xtremetech.net", response.NameServers[0]);
        Assert.Equal("ns6.e-xtremetech.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Expired", response.DomainStatus[0]);

        Assert.Equal(32, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "not-found", "not_found.txt");
        var response = parser.Parse("whois.tznic.or.tz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.tznic.or.tz/tz/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "found", "dailynews.co.tz.txt");
        var response = parser.Parse("whois.tznic.or.tz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.tznic.or.tz/tz/found/01", response.TemplateName);

        Assert.Equal("dailynews.co.tz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("REG-THL", response.Registrar.Name);

        Assert.Equal(new DateTime(2022, 06, 23, 13, 47, 22, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 07, 27, 11, 01, 10, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("TSN", response.Registrant.RegistryId);
        Assert.Null(response.Registrant.Name);
        Assert.Null(response.Registrant.Organization);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(0, response.Registrant.Address.Count);


        // AdminContact Details
        Assert.Equal("TSN", response.AdminContact.RegistryId);
        Assert.Null(response.AdminContact.Name);
        Assert.Null(response.AdminContact.Organization);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(0, response.AdminContact.Address.Count);


        // TechnicalContact Details
        Assert.Equal("TSN", response.TechnicalContact.RegistryId);
        Assert.Null(response.TechnicalContact.Name);
        Assert.Null(response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(0, response.TechnicalContact.Address.Count);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("hosting.nidc.co.tz", response.NameServers[0]);
        Assert.Equal("ns1.nidc.co.tz", response.NameServers[1]);

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(13, response.FieldsParsed);
    }
}
