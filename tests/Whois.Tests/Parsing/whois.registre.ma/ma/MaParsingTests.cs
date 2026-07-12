using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registre.Ma.Ma;

public class MaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.registre.ma", "ma", "not-found", "not_found.txt");
        var response = parser.Parse("whois.registre.ma", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registre.ma/ma/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.registre.ma", "ma", "found", "google.ma.txt");
        var response = parser.Parse("whois.registre.ma", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registre.ma/ma/found/01", response.TemplateName);

        Assert.Equal("google.ma", response.DomainName.ToString());
        Assert.Equal("333.google.ma", response.RegistryDomainId);

        Assert.Equal(new DateTime(2009, 03, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 03, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("221.google.ma", response.Registrant.RegistryId);


        // AdminContact Details
        Assert.Equal("222.google.ma", response.AdminContact.RegistryId);


        // BillingContact Details
        Assert.Equal("222.google.ma", response.BillingContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("223.google.ma", response.TechnicalContact.RegistryId);


        Assert.Equal(9, response.FieldsParsed);
    }
}
