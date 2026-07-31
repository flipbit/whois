using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cz.Cz;

public class CzParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CzParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.cz", "cz", "found", "found.txt");
        var response = parser.Parse("whois.nic.cz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cz/cz/found/01", response.TemplateName);

        Assert.Equal("rybarskepotreby-marek.cz", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 01, 04, 18, 57, 14, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 12, 31, 03, 39, 20, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("A24CONTACT-42407", response.Registrant.RegistryId);
        Assert.Equal("Leoš Marek", response.Registrant.Name);
        Assert.Equal("Leoš Marek", response.Registrant.Organization);
        Assert.Equal(new DateTime(2010, 12, 31, 03, 36, 50, 000, DateTimeKind.Utc), response.Registrant.Created);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Krásný Dvůr 180", response.Registrant.Address[0]);
        Assert.Equal("Krásný Dvůr", response.Registrant.Address[1]);
        Assert.Equal("43972", response.Registrant.Address[2]);
        Assert.Equal("CZ", response.Registrant.Address[3]);


        // TechnicalContact Details
        Assert.Equal("WEBAREAL-CZ", response.TechnicalContact.RegistryId);
        Assert.Equal("Jaroslav Hansal", response.TechnicalContact.Name);
        Assert.Equal("info@webareal.cz", response.TechnicalContact.Email);
        Assert.Equal(new DateTime(2009, 04, 10, 14, 48, 02, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Rudolfovská tř. 247/85", response.TechnicalContact.Address[0]);
        Assert.Equal("České Budějovice", response.TechnicalContact.Address[1]);
        Assert.Equal("37001", response.TechnicalContact.Address[2]);
        Assert.Equal("CZ", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns.unihost.cz", response.NameServers[0]);
        Assert.Equal("ns2.unihost.cz", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("paid and in zone", response.DomainStatus[0]);

        Assert.Equal(27, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.nic.cz", "cz", "throttled", "throttled.txt");
        var response = parser.Parse("whois.nic.cz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cz/cz/throttled/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_response_with_keyset()
    {
        var sample = SampleReader.Read("whois.nic.cz", "cz", "found", "found_response_with_keyset.txt");
        var response = parser.Parse("whois.nic.cz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cz/cz/found/01", response.TemplateName);

        Assert.Equal("realityporno.cz", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 10, 07, 21, 51, 15, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2006, 01, 30, 18, 55, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 01, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("SB:GLOBE-SPKA040146", response.Registrant.RegistryId);
        Assert.Equal("PK62, a.s", response.Registrant.Name);
        Assert.Equal("PK62, a.s", response.Registrant.Organization);
        Assert.Equal("domeny@pk62.cz", response.Registrant.Email);
        Assert.Equal(new DateTime(2004, 11, 19, 15, 05, 00, 000, DateTimeKind.Utc), response.Registrant.Created);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Bohdalecka 6/1420", response.Registrant.Address[0]);
        Assert.Equal("Praha 10", response.Registrant.Address[1]);
        Assert.Equal("10100", response.Registrant.Address[2]);
        Assert.Equal("CZ", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("GLOBE-PKVO462567", response.AdminContact.RegistryId);
        Assert.Equal("Pavel Kvoriak", response.AdminContact.Name);
        Assert.Equal("domeny@pk62.cz", response.AdminContact.Email);
        Assert.Equal(new DateTime(2004, 11, 19, 14, 05, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Bohdalecka 6/1420", response.AdminContact.Address[0]);
        Assert.Equal("Praha 10", response.AdminContact.Address[1]);
        Assert.Equal("10100", response.AdminContact.Address[2]);
        Assert.Equal("CZ", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("ACTIVE24", response.TechnicalContact.RegistryId);
        Assert.Equal("ACTIVE 24, s.r.o.", response.TechnicalContact.Name);
        Assert.Equal("ACTIVE 24, s.r.o.", response.TechnicalContact.Organization);
        Assert.Equal(new DateTime(2008, 04, 29, 12, 35, 02, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Sokolovská 394/17", response.TechnicalContact.Address[0]);
        Assert.Equal("Praha 8", response.TechnicalContact.Address[1]);
        Assert.Equal("186 00", response.TechnicalContact.Address[2]);
        Assert.Equal("CZ", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("beta.ns.active24.cz", response.NameServers[0]);
        Assert.Equal("gama.ns.active24.sk", response.NameServers[1]);
        Assert.Equal("alfa.ns.active24.cz", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("paid and in zone", response.DomainStatus[0]);

        Assert.Equal(42, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.cz", "cz", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.cz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cz/cz/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.cz", "cz", "found", "google.cz.txt");
        var response = parser.Parse("whois.nic.cz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cz/cz/found/01", response.TemplateName);

        Assert.Equal("google.cz", response.DomainName.ToString());

        Assert.Equal(new DateTime(2021, 06, 29, 23, 29, 20, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2000, 07, 21, 15, 21, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 07, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("MM1171195", response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("Google LLC", response.Registrant.Organization);
        Assert.Null(response.Registrant.Email);
        Assert.Equal(new DateTime(2018, 03, 02, 18, 52, 05, 000, DateTimeKind.Utc), response.Registrant.Created);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("94043", response.Registrant.Address[2]);
        Assert.Equal("CA", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("MM1171195", response.AdminContact.RegistryId);
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("Google LLC", response.AdminContact.Organization);
        Assert.Null(response.AdminContact.Email);
        Assert.Equal(new DateTime(2018, 03, 02, 18, 52, 05, 000, DateTimeKind.Utc), response.AdminContact.Created);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("94043", response.AdminContact.Address[2]);
        Assert.Equal("CA", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("MM193020", response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Provisioning", response.TechnicalContact.Name);
        Assert.Equal("MarkMonitor Inc.", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.Email);
        Assert.Equal(new DateTime(2011, 02, 03, 18, 24, 34, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("2150 S Bonito Way", response.TechnicalContact.Address[0]);
        Assert.Equal("Suite 150", response.TechnicalContact.Address[1]);
        Assert.Equal("Meridian", response.TechnicalContact.Address[2]);
        Assert.Equal("83642", response.TechnicalContact.Address[3]);
        Assert.Equal("ID", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns2.google.com", response.NameServers[0]);
        Assert.Equal("ns4.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns1.google.com", response.NameServers[3]);

        Assert.Equal(35, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_phoca_cz()
    {
        var sample = SampleReader.Read("whois.nic.cz", "cz", "found", "phoca.cz.txt");

        var response = parser.Parse("whois.nic.cz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cz/cz/found/01", response.TemplateName);

        Assert.Equal("phoca.cz", response.DomainName.ToString());

        Assert.Equal(new DateTime(2018, 05, 15, 21, 32, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2007, 08, 08, 07, 15, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2019, 08, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("SB:SUB000029824-ZONER", response.Registrant.RegistryId);
        Assert.Equal("Lenka Medunová", response.Registrant.Name);
        Assert.Equal(new DateTime(2007, 08, 08, 06, 55, 00, 000, DateTimeKind.Utc), response.Registrant.Created);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Bratrstva 38", response.Registrant.Address[0]);
        Assert.Equal("Znojmo", response.Registrant.Address[1]);
        Assert.Equal("66902", response.Registrant.Address[2]);
        Assert.Equal("CZ", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("PER000029824-ZONER", response.AdminContact.RegistryId);
        Assert.Equal("Lenka Medunová", response.AdminContact.Name);
        Assert.Equal(new DateTime(2007, 08, 08, 06, 15, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Bratrstva 38", response.AdminContact.Address[0]);
        Assert.Equal("Znojmo", response.AdminContact.Address[1]);
        Assert.Equal("66902", response.AdminContact.Address[2]);
        Assert.Equal("CZ", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("SB:SUB100000001-ZONER", response.TechnicalContact.RegistryId);
        Assert.Equal("ZONER software a.s.", response.TechnicalContact.Name);
        Assert.Equal("ZONER software a.s.", response.TechnicalContact.Organization);
        Assert.Equal(new DateTime(2001, 08, 10, 22, 13, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Nové sady 18", response.TechnicalContact.Address[0]);
        Assert.Equal("Brno", response.TechnicalContact.Address[1]);
        Assert.Equal("60200", response.TechnicalContact.Address[2]);
        Assert.Equal("CZ", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns2.videon-znojmo.cz", response.NameServers[0]);
        Assert.Equal("ns1.videon-znojmo.cz", response.NameServers[1]);

        Assert.Equal(44, response.FieldsParsed);
    }
}
