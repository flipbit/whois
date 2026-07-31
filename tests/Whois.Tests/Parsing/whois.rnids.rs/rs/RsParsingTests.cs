using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Rnids.Rs.Rs;

public class RsParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public RsParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.rnids.rs", "rs", "found", "eg.rs.txt");
        var response = parser.Parse("whois.rnids.rs", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rnids.rs/rs/found/01", response.TemplateName);

        Assert.Equal("eg", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("GAMA Electronics d.o.o.", response.Registrar.Name);

        Assert.Equal(new DateTime(2025, 10, 04, 09, 31, 52, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(8, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_nameservers_hyphenated()
    {
        var sample = SampleReader.Read("whois.rnids.rs", "rs", "found", "found_nameservers_hyphenated.txt");
        var response = parser.Parse("whois.rnids.rs", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rnids.rs/rs/found/01", response.TemplateName);

        Assert.Equal("eg.rs", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("GAMA Electronics d.o.o.", response.Registrar.Name);

        Assert.Equal(new DateTime(2011, 08, 08, 11, 13, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 10, 22, 10, 20, 31, 000, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("bits-hq.bitsyu.net", response.NameServers[0]);
        Assert.Equal("largo.bitsyu.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_expired()
    {
        var sample = SampleReader.Read("whois.rnids.rs", "rs", "expired", "expired.txt");
        var response = parser.Parse("whois.rnids.rs", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Expired, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rnids.rs/rs/found/01", response.TemplateName);

        Assert.Equal("saj-expired.rs", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("BGSVETIONIK.S.A.", response.Registrar.Name);

        Assert.Equal(new DateTime(2012, 06, 18, 02, 00, 02, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 06, 17, 14, 40, 59, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 06, 17, 14, 40, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Ana Rakovic", response.Registrant.Name);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns9.sajthosting.com", response.NameServers[0]);
        Assert.Equal("ns10.sajthosting.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Expired", response.DomainStatus[0]);

        Assert.Equal(10, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_in_transfer()
    {
        var sample = SampleReader.Read("whois.rnids.rs", "rs", "found", "saj.rs.txt");
        var response = parser.Parse("whois.rnids.rs", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rnids.rs/rs/found/01", response.TemplateName);

        Assert.Equal("saj", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Gransy d.o.o.", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 07, 06, 20, 36, 15, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2020, 07, 20, 16, 16, 09, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 07, 20, 16, 16, 09, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant.Name);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(8, response.FieldsParsed);
    }

    [Fact]
    public void Test_locked()
    {
        var sample = SampleReader.Read("whois.rnids.rs", "rs", "locked", "locked.txt");
        var response = parser.Parse("whois.rnids.rs", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Locked, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rnids.rs/rs/found/01", response.TemplateName);

        Assert.Equal("kondor.rs", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("BGSVETIONIK.S.A.", response.Registrar.Name);

        Assert.Equal(new DateTime(2011, 11, 18, 16, 03, 46, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 09, 30, 16, 19, 08, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 09, 30, 16, 19, 08, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Slavisa Janjusevic", response.Registrant.Name);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("dns1.orion.rs", response.NameServers[0]);
        Assert.Equal("dns2.orion.rs", response.NameServers[1]);
        Assert.Equal("dns3.orion.rs", response.NameServers[2]);
        Assert.Equal("dns4.orion.rs", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Locked", response.DomainStatus[0]);

        Assert.Equal(12, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.rnids.rs", "rs", "not-found", "not_found.txt");
        var response = parser.Parse("whois.rnids.rs", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rnids.rs/rs/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.rnids.rs", "rs", "found", "google.rs.txt");
        var response = parser.Parse("whois.rnids.rs", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rnids.rs/rs/found/01", response.TemplateName);

        Assert.Equal("google", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Webglobe d.o.o.", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 02, 17, 22, 18, 21, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 03, 10, 12, 31, 19, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 03, 10, 12, 31, 19, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant.Name);

        // Registrant Address
        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway, Mountain View, CA 94043, United States of America", response.Registrant.Address[0]);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(9, response.FieldsParsed);
    }
}
