using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.Lk;

public class LkParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public LkParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.lk", "lk", "found", "found.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lk/found/01", response.TemplateName);

        Assert.Equal("nestle.lk", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 03, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2019, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Nestle Lanka Ltd.", response.Registrant.Name);

        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("aoadns1.nestle.com.", response.NameServers[0]);
        Assert.Equal("ctrdns1.nestle.com.", response.NameServers[1]);
        Assert.Equal("ctrdns1.nestle.com.", response.NameServers[2]);

        Assert.Equal(8, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_updated_on_null()
    {
        var sample = SampleReader.Read("whois.nic.lk", "lk", "found", "found_updated_on_null.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lk/found/01", response.TemplateName);

        Assert.Equal("clear.lk", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 11, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 11, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("WELIGAMA HOTEL PROPERTIES LIMITED", response.Registrant.Name);

        Assert.Equal(5, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.lk", "lk", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lk/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.lk", "lk", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.lk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.lk/found/01", response.TemplateName);

        Assert.Equal("google.lk", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 03, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Google Inc.", response.Registrant.Name);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com.", response.NameServers[0]);
        Assert.Equal("ns2.google.com.", response.NameServers[1]);

        Assert.Equal(8, response.FieldsParsed);
    }
}
