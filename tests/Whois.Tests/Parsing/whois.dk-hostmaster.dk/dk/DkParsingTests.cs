using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dk.Hostmaster.Dk.Dk;

public class DkParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public DkParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_deactivated()
    {
        var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "deactivated", "deactivated.txt");
        var response = parser.Parse("whois.dk-hostmaster.dk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Deactivated, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dk-hostmaster.dk/dk/found/01", response.TemplateName);

        Assert.Equal("progolftours.dk", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 08, 16, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2012, 08, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("LI1233-DK", response.Registrant.RegistryId);
        Assert.Equal("LH Invest", response.Registrant.Name);
        Assert.Equal("+4520645320", response.Registrant.TelephoneNumber);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Hausergade 36 1th", response.Registrant.Address[0]);
        Assert.Equal("1128", response.Registrant.Address[1]);
        Assert.Equal("København K", response.Registrant.Address[2]);
        Assert.Equal("DK", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("LI1233-DK", response.AdminContact.RegistryId);
        Assert.Equal("LH Invest", response.AdminContact.Name);
        Assert.Equal("+4520645320", response.AdminContact.TelephoneNumber);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Hausergade 36 1th", response.AdminContact.Address[0]);
        Assert.Equal("1128", response.AdminContact.Address[1]);
        Assert.Equal("København K", response.AdminContact.Address[2]);
        Assert.Equal("DK", response.AdminContact.Address[3]);


        // Nameservers
        Assert.Equal(5, response.NameServers.Count);
        Assert.Equal("ns1.gratisdns.dk", response.NameServers[0]);
        Assert.Equal("ns2.gratisdns.dk", response.NameServers[1]);
        Assert.Equal("ns3.gratisdns.dk", response.NameServers[2]);
        Assert.Equal("ns4.gratisdns.dk", response.NameServers[3]);
        Assert.Equal("ns5.gratisdns.dk", response.NameServers[4]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Deactivated", response.DomainStatus[0]);

        Assert.Equal(24, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "reserved", "reserved.txt");
        var response = parser.Parse("whois.dk-hostmaster.dk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dk-hostmaster.dk/dk/found/01", response.TemplateName);

        Assert.Equal("googlle.dk", response.DomainName.ToString());

        Assert.Equal(new DateTime(2013, 10, 24, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 10, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Reserved", response.DomainStatus[0]);

        Assert.Equal(5, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "throttled", "throttled.txt");
        var response = parser.Parse("whois.dk-hostmaster.dk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dk-hostmaster.dk/dk/throttled/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled_response_throttled()
    {
        var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "throttled", "throttled_response_throttled.txt");
        var response = parser.Parse("whois.dk-hostmaster.dk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dk-hostmaster.dk/dk/throttled/02", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "not-found", "not_found.txt");
        var response = parser.Parse("whois.dk-hostmaster.dk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dk-hostmaster.dk/dk/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "found", "google.dk.txt");
        var response = parser.Parse("whois.dk-hostmaster.dk", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dk-hostmaster.dk/dk/found/01", response.TemplateName);

        Assert.Equal("google.dk", response.DomainName.ToString());

        Assert.Equal(new DateTime(1999, 1, 10, 0, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 3, 31, 0, 0, 0, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(5, response.FieldsParsed);
    }
}
