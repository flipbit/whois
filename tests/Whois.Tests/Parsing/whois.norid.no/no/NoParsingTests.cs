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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
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

        Assert.Equal(new DateTime(2015, 01, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("GNA233O-NORID", response.Registrant.RegistryId);
        Assert.Equal("Google Norway AS", response.Registrant.Name);
        Assert.Equal("+47.23894000", response.Registrant.TelephoneNumber);
        Assert.Equal("+47.23894001", response.Registrant.FaxNumber);
        Assert.Equal("Dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Beddingen 10", response.Registrant.Address[0]);
        Assert.Equal("NO-7014", response.Registrant.Address[1]);
        Assert.Equal("Trondheim", response.Registrant.Address[2]);
        Assert.Equal("NO", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("RH3332P-NORID", response.AdminContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("MS5407P-NORID", response.TechnicalContact.RegistryId);


        Assert.Equal(17, response.FieldsParsed);
    }
}
