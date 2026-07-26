using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Priv.At.At;

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
        var sample = SampleReader.Read("whois.nic.priv.at", "at", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.priv.at", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.priv.at/at/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.priv.at", "at", "found", "nic.priv.at.txt");
        var response = parser.Parse("whois.nic.priv.at", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.priv.at/at/found/01", response.TemplateName);

        Assert.Equal("nic.priv.at", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Network Information Center for priv.at", response.Registrar.Name);
        Assert.Equal("hostmaster@nic.priv.at", response.Registrar.AbuseEmail);

        Assert.Equal(new DateTime(2002, 10, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);

        // AdminContact Details
        Assert.Equal("HM-PRIVAT", response.AdminContact.RegistryId);
        Assert.Null(response.AdminContact.Name);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(0, response.AdminContact.Address.Count);


        // TechnicalContact Details
        Assert.Equal("HM-PRIVAT", response.TechnicalContact.RegistryId);
        Assert.Null(response.TechnicalContact.Name);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(0, response.TechnicalContact.Address.Count);


        // ZoneContact Details
        Assert.Equal("HM-PRIVAT", response.ZoneContact.RegistryId);
        Assert.Null(response.ZoneContact.Name);
        Assert.Null(response.ZoneContact.Email);

        // ZoneContact Address
        Assert.Equal(0, response.ZoneContact.Address.Count);


        Assert.Equal(8, response.FieldsParsed);
    }
}
