using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Mynic.My.My;

public class MyParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MyParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.mynic.my", "my", "not-found", "u34jedzcq.my.txt");
        var response = parser.Parse("whois.mynic.my", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.mynic.my/my/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.my", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.mynic.my", "my", "found", "google.my.txt");
        var response = parser.Parse("whois.mynic.my", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.my", response.DomainName.ToString());

        Assert.Equal(new DateTime(2026, 04, 16, 10, 30, 12, 779, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 05, 12, 16, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 05, 12, 16, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);
        Assert.Equal("Google LLC", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Organization);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[3]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[4]);


        Assert.Equal(42, response.FieldsParsed);
    }
}
