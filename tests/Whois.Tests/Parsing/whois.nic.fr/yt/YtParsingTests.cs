using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fr.Yt;

public class YtParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public YtParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.nic.fr", "yt", "throttled", "throttled.txt");
        var response = parser.Parse("whois.nic.fr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/throttled/02", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.fr", "yt", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.fr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/06", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.fr", "yt", "found", "found.txt");
        var response = parser.Parse("whois.nic.fr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/05", response.TemplateName);

        Assert.Equal("nic.yt", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("AFNIC registry", response.Registrar.Name);

        Assert.Equal(new DateTime(2016, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1995, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2017, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("AC3598-FRNIC", response.Registrant.RegistryId);
        Assert.Equal("Afnic (Mayotte - CTOM)", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("immeuble international", response.Registrant.Address[0]);
        Assert.Equal("2, rue Stephenson", response.Registrant.Address[1]);
        Assert.Equal("Montigny-Le-Bretonneux", response.Registrant.Address[2]);
        Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.Registrant.Address[3]);
        Assert.Equal("FR", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("NFC1-FRNIC", response.AdminContact.RegistryId);
        Assert.Equal("NIC France Contact", response.AdminContact.Name);
        Assert.Equal("+33 1 39 30 83 00", response.AdminContact.TelephoneNumber);
        Assert.Equal("hostmaster@nic.fr", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(6, response.AdminContact.Address.Count);
        Assert.Equal("AFNIC", response.AdminContact.Address[0]);
        Assert.Equal("immeuble international", response.AdminContact.Address[1]);
        Assert.Equal("2, rue Stephenson", response.AdminContact.Address[2]);
        Assert.Equal("Montigny le Bretonneux", response.AdminContact.Address[3]);
        Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.AdminContact.Address[4]);
        Assert.Equal("FR", response.AdminContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("NFC1-FRNIC", response.TechnicalContact.RegistryId);
        Assert.Equal("NIC France Contact", response.TechnicalContact.Name);
        Assert.Equal("+33 1 39 30 83 00", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("hostmaster@nic.fr", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("AFNIC", response.TechnicalContact.Address[0]);
        Assert.Equal("immeuble international", response.TechnicalContact.Address[1]);
        Assert.Equal("2, rue Stephenson", response.TechnicalContact.Address[2]);
        Assert.Equal("Montigny le Bretonneux", response.TechnicalContact.Address[3]);
        Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.TechnicalContact.Address[4]);
        Assert.Equal("FR", response.TechnicalContact.Address[5]);


        // ZoneContact Details
        Assert.Equal("NFC1-FRNIC", response.ZoneContact.RegistryId);
        Assert.Equal("NIC France Contact", response.ZoneContact.Name);
        Assert.Equal("+33 1 39 30 83 00", response.ZoneContact.TelephoneNumber);
        Assert.Equal("hostmaster@nic.fr", response.ZoneContact.Email);

        // ZoneContact Address
        Assert.Equal(6, response.ZoneContact.Address.Count);
        Assert.Equal("AFNIC", response.ZoneContact.Address[0]);
        Assert.Equal("immeuble international", response.ZoneContact.Address[1]);
        Assert.Equal("2, rue Stephenson", response.ZoneContact.Address[2]);
        Assert.Equal("Montigny le Bretonneux", response.ZoneContact.Address[3]);
        Assert.Equal("78181 Saint Quentin en Yvelines Cedex", response.ZoneContact.Address[4]);
        Assert.Equal("FR", response.ZoneContact.Address[5]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.nic.fr", response.NameServers[0]);
        Assert.Equal("ns2.nic.fr", response.NameServers[1]);
        Assert.Equal("ns3.nic.fr", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVE", response.DomainStatus[0]);

        Assert.Equal(32, response.FieldsParsed);
    }
}
