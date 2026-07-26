using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Hkirc.Hk.Hk;

public class HkParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public HkParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.hkirc.hk", "hk", "found", "brighter.com.hk.txt");
        var response = parser.Parse("whois.hkirc.hk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.hkirc.hk/hk/found/01", response.TemplateName);

        Assert.Equal("brighter.com.hk", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Hong Kong Domain Name Registration Company Limited", response.Registrar.Name);
        Assert.Equal("enquiry@hkdnr.hk", response.Registrar.AbuseEmail);
        Assert.Equal("+852 2319 1313", response.Registrar.AbuseTelephoneNumber);

        Assert.Null(response.Registered);

        // Registrant Details
        Assert.Equal("THE BRIGHTER CO", response.Registrant.Name);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(0, response.Registrant.Address.Count);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.hkirc.hk", "hk", "not-found", "not_found.txt");
        var response = parser.Parse("whois.hkirc.hk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.hkirc.hk/hk/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.hkirc.hk", "hk", "found", "google.hk.txt");
        var response = parser.Parse("whois.hkirc.hk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.hkirc.hk/hk/found/01", response.TemplateName);

        Assert.Equal("google.hk", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MARKMONITOR INC.", response.Registrar.Name);

        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Equal("GOOGLE LLC", response.Registrant.Name);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(0, response.Registrant.Address.Count);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(4, response.FieldsParsed);
    }
}
