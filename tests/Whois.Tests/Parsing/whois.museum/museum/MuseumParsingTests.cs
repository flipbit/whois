using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Museum.Museum;

public class MuseumParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MuseumParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.museum", "museum", "not-found", "u34jedzcq.museum.txt");
        var response = parser.Parse("whois.museum", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.museum", "museum", "found", "musedoma.museum.txt");
        var response = parser.Parse("whois.museum", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("musedoma.museum", response.DomainName.ToString());
        Assert.Equal("DOM000000000915-MUSEUM", response.RegistryDomainId);


        // Registrant Details
        Assert.Equal("REDACTED_FOR_PRIVACY", response.Registrant.RegistryId);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.Registrant.Name);
        Assert.Null(response.Registrant.Organization);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.Registrant.Address[2]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("REDACTED_FOR_PRIVACY", response.AdminContact.RegistryId);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.AdminContact.Name);
        Assert.Null(response.AdminContact.Organization);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY", response.AdminContact.Address[0]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.AdminContact.Address[1]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.AdminContact.Address[2]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.AdminContact.Address[3]);


        // BillingContact Details
        Assert.Equal("REDACTED_FOR_PRIVACY", response.BillingContact.RegistryId);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.BillingContact.Name);
        Assert.Null(response.BillingContact.Organization);
        Assert.Null(response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY", response.BillingContact.Address[0]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.BillingContact.Address[1]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.BillingContact.Address[2]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.BillingContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("REDACTED_FOR_PRIVACY", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.TechnicalContact.Name);
        Assert.Null(response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY, REDACTED_FOR_PRIVACY", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED_FOR_PRIVACY", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("primary.heberge.info", response.NameServers[0]);

        // Domain Status
        Assert.Equal(9, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal(49, response.FieldsParsed);
    }
}
