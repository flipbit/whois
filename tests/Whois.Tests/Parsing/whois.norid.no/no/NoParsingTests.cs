using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Norid.No.No;

public class NoParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public NoParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.norid.no", "no", "not-found", "not_found.txt");
        var response = parser.Parse("whois.norid.no", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.norid.no/no/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.norid.no", "no", "found", "google.no.txt");
        var response = parser.Parse("whois.norid.no", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.norid.no/no/found/01", response.TemplateName);

        Assert.Equal("google.no", response.DomainName.ToString());
        Assert.Equal("GOO371D-NORID", response.RegistryDomainId);

        Assert.Equal(new DateTime(2026, 01, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Equal("GL14R-NORID", response.TechnicalContact.RegistryId);


        Assert.Equal(6, response.FieldsParsed);
    }
}
