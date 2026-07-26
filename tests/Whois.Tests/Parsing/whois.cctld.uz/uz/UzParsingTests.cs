using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cctld.Uz.Uz;

public class UzParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public UzParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.cctld.uz", "uz", "reserved", "cctld.uz.txt");
        var response = parser.Parse("whois.cctld.uz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("cctld.uz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("ЕИ UZINFOCOM Администрация", response.Registrar.Name);
        Assert.Null(response.Registrar.Url);
        Assert.Null(response.Registrar.WhoisServer);

        Assert.Equal(new DateTime(2025, 1, 16, 0, 0, 0), response.Updated);
        Assert.Equal(new DateTime(2005, 5, 1, 0, 0, 0), response.Registered);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address



        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("RESERVED", response.DomainStatus[0]);

        Assert.Equal(7, response.FieldsParsed);
        AssertWriter.Write(response);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.cctld.uz", "uz", "not-found", "u34jedzcq.uz.txt");
        var response = parser.Parse("whois.cctld.uz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.cctld.uz/uz/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.uz", response.DomainName.ToString());


        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.cctld.uz", "uz", "found", "google.uz.txt");
        var response = parser.Parse("whois.cctld.uz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.uz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Tomas", response.Registrar.Name);
        Assert.Null(response.Registrar.Url);
        Assert.Null(response.Registrar.WhoisServer);

        Assert.Equal(new DateTime(2026, 4, 28, 0, 0, 0), response.Updated);
        Assert.Equal(new DateTime(2006, 4, 13, 0, 0, 0), response.Registered);
        Assert.Equal(new DateTime(2027, 5, 1, 0, 0, 0), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("ACTIVE", response.DomainStatus[0]);

        Assert.Equal(8, response.FieldsParsed);
    }
}
