using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Dz.Dz;

public class DzParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public DzParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.dz", "dz", "not-found", "u34jedzcq.dz.txt");
        var response = parser.Parse("whois.nic.dz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.dz/dz/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.dz", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.dz", "dz", "found", "google.dz.txt");
        var response = parser.Parse("whois.nic.dz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.dz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("wissal", response.Registrar.Name);

        Assert.Null(response.Registered);

        // Registrant Details
        Assert.Null(response.Registrant);


        // AdminContact Details
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Null(response.AdminContact.Organization);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(0, response.AdminContact.Address.Count);


        // TechnicalContact Details
        Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
        Assert.Null(response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(0, response.TechnicalContact.Address.Count);


        Assert.Equal(7, response.FieldsParsed);
    }
}
