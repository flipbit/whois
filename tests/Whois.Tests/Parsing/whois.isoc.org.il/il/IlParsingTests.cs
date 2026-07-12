using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Isoc.Org.Il.Il;

public class IlParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public IlParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.isoc.org.il", "il", "not-found", "not_found.txt");
        var response = parser.Parse("whois.isoc.org.il", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.isoc.org.il/il/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_transfer_allowed()
    {
        var sample = SampleReader.Read("whois.isoc.org.il", "il", "found", "other_status_transfer_allowed.txt");
        var response = parser.Parse("whois.isoc.org.il", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.isoc.org.il/il/found/01", response.TemplateName);

        Assert.Equal("spd.co.il", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Israel Internet Association ISOC-IL", response.Registrar.Name);
        Assert.Equal("www.isoc.org.il", response.Registrar.Url);

        Assert.Equal(new DateTime(2005, 01, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 08, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 08, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("avi hirsh", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("beeri 17", response.Registrant.Address[0]);
        Assert.Equal("ganney tikva", response.Registrant.Address[1]);
        Assert.Equal("55900", response.Registrant.Address[2]);
        Assert.Equal("Israel", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("II-AH9666-IL", response.AdminContact.RegistryId);
        Assert.Equal("avi hirsh", response.AdminContact.Name);
        Assert.Equal("972-68-719751", response.AdminContact.TelephoneNumber);
        Assert.Equal("admin@spd.co.il", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("sPD", response.AdminContact.Address[0]);
        Assert.Equal("beeri 23", response.AdminContact.Address[1]);
        Assert.Equal("ganney tikva", response.AdminContact.Address[2]);
        Assert.Equal("55900", response.AdminContact.Address[3]);
        Assert.Equal("Israel", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("II-AH9666-IL", response.TechnicalContact.RegistryId);
        Assert.Equal("avi hirsh", response.TechnicalContact.Name);
        Assert.Equal("972-68-719751", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("admin@spd.co.il", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("sPD", response.TechnicalContact.Address[0]);
        Assert.Equal("beeri 23", response.TechnicalContact.Address[1]);
        Assert.Equal("ganney tikva", response.TechnicalContact.Address[2]);
        Assert.Equal("55900", response.TechnicalContact.Address[3]);
        Assert.Equal("Israel", response.TechnicalContact.Address[4]);


        // ZoneContact Details
        Assert.Equal("II-AH9666-IL", response.ZoneContact.RegistryId);
        Assert.Equal("avi hirsh", response.ZoneContact.Name);
        Assert.Equal("972-68-719751", response.ZoneContact.TelephoneNumber);
        Assert.Equal("admin@spd.co.il", response.ZoneContact.Email);

        // ZoneContact Address
        Assert.Equal(5, response.ZoneContact.Address.Count);
        Assert.Equal("sPD", response.ZoneContact.Address[0]);
        Assert.Equal("beeri 23", response.ZoneContact.Address[1]);
        Assert.Equal("ganney tikva", response.ZoneContact.Address[2]);
        Assert.Equal("55900", response.ZoneContact.Address[3]);
        Assert.Equal("Israel", response.ZoneContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns11.spd.co.il", response.NameServers[0]);
        Assert.Equal("ns12.spd.co.il", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Transfer Allowed", response.DomainStatus[0]);

        Assert.Equal(28, response.FieldsParsed);
    }

    [Fact]
    public void Test_locked()
    {
        var sample = SampleReader.Read("whois.isoc.org.il", "il", "locked", "locked.txt");
        var response = parser.Parse("whois.isoc.org.il", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Locked, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.isoc.org.il/il/found/01", response.TemplateName);

        Assert.Equal("isoc-locked.org.il", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Israel Internet Association ISOC-IL", response.Registrar.Name);
        Assert.Equal("www.isoc-locked.org.il", response.Registrar.Url);

        Assert.Equal(new DateTime(2010, 10, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1996, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Israel Internet Association (ISOC-IL)", response.Registrant.Name);
        Assert.Equal("+972 3 9700900", response.Registrant.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.Registrant.FaxNumber);
        Assert.Equal("info-domains@isoc-locked.org.il", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("6 Bareket st., POB 7210", response.Registrant.Address[0]);
        Assert.Equal("Petach Tikva", response.Registrant.Address[1]);
        Assert.Equal("49517", response.Registrant.Address[2]);
        Assert.Equal("Israel", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("II-DS1453-IL", response.AdminContact.RegistryId);
        Assert.Equal("Doron Shikmoni", response.AdminContact.Name);
        Assert.Equal("+972 3 9700900", response.AdminContact.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.AdminContact.FaxNumber);
        Assert.Equal("doron@isoc-locked.org.il", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Israel Internet Association (ISOC-IL)", response.AdminContact.Address[0]);
        Assert.Equal("6 Bareket st., POB 7210", response.AdminContact.Address[1]);
        Assert.Equal("Petach Tikva", response.AdminContact.Address[2]);
        Assert.Equal("49517", response.AdminContact.Address[3]);
        Assert.Equal("Israel", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("II-AB17965-IL", response.TechnicalContact.RegistryId);
        Assert.Equal("Ariel Biener", response.TechnicalContact.Name);
        Assert.Equal("+972 3 9700900", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.TechnicalContact.FaxNumber);
        Assert.Equal("ariel@isoc-locked.org.il", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Israel Internet Associaiton (ISOC-IL)", response.TechnicalContact.Address[0]);
        Assert.Equal("6 Bareket st., POB 7210", response.TechnicalContact.Address[1]);
        Assert.Equal("Petach Tikva", response.TechnicalContact.Address[2]);
        Assert.Equal("49517", response.TechnicalContact.Address[3]);
        Assert.Equal("Israel", response.TechnicalContact.Address[4]);


        // ZoneContact Details
        Assert.Equal("II-DS1453-IL", response.ZoneContact.RegistryId);
        Assert.Equal("Doron Shikmoni", response.ZoneContact.Name);
        Assert.Equal("+972 3 9700900", response.ZoneContact.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.ZoneContact.FaxNumber);
        Assert.Equal("doron@isoc-locked.org.il", response.ZoneContact.Email);

        // ZoneContact Address
        Assert.Equal(5, response.ZoneContact.Address.Count);
        Assert.Equal("Israel Internet Association (ISOC-IL)", response.ZoneContact.Address[0]);
        Assert.Equal("6 Bareket st., POB 7210", response.ZoneContact.Address[1]);
        Assert.Equal("Petach Tikva", response.ZoneContact.Address[2]);
        Assert.Equal("49517", response.ZoneContact.Address[3]);
        Assert.Equal("Israel", response.ZoneContact.Address[4]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("ns.isoc-locked.org.il", response.NameServers[0]);
        Assert.Equal("grappa.isoc-locked.org.il", response.NameServers[1]);
        Assert.Equal("aristo.tau.ac.il", response.NameServers[2]);
        Assert.Equal("relay.huji.ac.il", response.NameServers[3]);
        Assert.Equal("drns.isoc-locked.org.il", response.NameServers[4]);
        Assert.Equal("sps-pb.isc.org", response.NameServers[5]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Transfer Locked", response.DomainStatus[0]);

        Assert.Equal(57, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found_status_available()
    {
        var sample = SampleReader.Read("whois.isoc.org.il", "il", "not-found", "not_found_status_available.txt");
        var response = parser.Parse("whois.isoc.org.il", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.isoc.org.il/il/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.isoc.org.il", "il", "found", "found.txt");
        var response = parser.Parse("whois.isoc.org.il", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Locked, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.isoc.org.il/il/found/01", response.TemplateName);

        Assert.Equal("isoc.org.il", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Israel Internet Association ISOC-IL", response.Registrar.Name);
        Assert.Equal("www.isoc.org.il", response.Registrar.Url);

        Assert.Equal(new DateTime(2014, 01, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1996, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Israel Internet Association (ISOC-IL)", response.Registrant.Name);
        Assert.Equal("+972 3 9700900", response.Registrant.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.Registrant.FaxNumber);
        Assert.Equal("info-domains@isoc.org.il", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("6 Bareket st., POB 7210", response.Registrant.Address[0]);
        Assert.Equal("Petach Tikva", response.Registrant.Address[1]);
        Assert.Equal("49517", response.Registrant.Address[2]);
        Assert.Equal("Israel", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("II-DB11403-IL", response.AdminContact.RegistryId);
        Assert.Equal("Dina Beer", response.AdminContact.Name);
        Assert.Equal("+972 3 9700900", response.AdminContact.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.AdminContact.FaxNumber);
        Assert.Equal("dina.b@isoc.org.il", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Israel Internet Association (ISOC-IL)", response.AdminContact.Address[0]);
        Assert.Equal("6 Bareket st., POB 7210", response.AdminContact.Address[1]);
        Assert.Equal("Petach Tikva", response.AdminContact.Address[2]);
        Assert.Equal("49517", response.AdminContact.Address[3]);
        Assert.Equal("Israel", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("II-DB11403-IL", response.TechnicalContact.RegistryId);
        Assert.Equal("Dina Beer", response.TechnicalContact.Name);
        Assert.Equal("+972 3 9700900", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.TechnicalContact.FaxNumber);
        Assert.Equal("dina.b@isoc.org.il", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Israel Internet Association (ISOC-IL)", response.TechnicalContact.Address[0]);
        Assert.Equal("6 Bareket st., POB 7210", response.TechnicalContact.Address[1]);
        Assert.Equal("Petach Tikva", response.TechnicalContact.Address[2]);
        Assert.Equal("49517", response.TechnicalContact.Address[3]);
        Assert.Equal("Israel", response.TechnicalContact.Address[4]);


        // ZoneContact Details
        Assert.Equal("II-DB11403-IL", response.ZoneContact.RegistryId);
        Assert.Equal("Dina Beer", response.ZoneContact.Name);
        Assert.Equal("+972 3 9700900", response.ZoneContact.TelephoneNumber);
        Assert.Equal("+972 3 9700901", response.ZoneContact.FaxNumber);
        Assert.Equal("dina.b@isoc.org.il", response.ZoneContact.Email);

        // ZoneContact Address
        Assert.Equal(5, response.ZoneContact.Address.Count);
        Assert.Equal("Israel Internet Association (ISOC-IL)", response.ZoneContact.Address[0]);
        Assert.Equal("6 Bareket st., POB 7210", response.ZoneContact.Address[1]);
        Assert.Equal("Petach Tikva", response.ZoneContact.Address[2]);
        Assert.Equal("49517", response.ZoneContact.Address[3]);
        Assert.Equal("Israel", response.ZoneContact.Address[4]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("ns.isoc.org.il", response.NameServers[0]);
        Assert.Equal("grappa.isoc.org.il", response.NameServers[1]);
        Assert.Equal("aristo.tau.ac.il", response.NameServers[2]);
        Assert.Equal("relay.huji.ac.il", response.NameServers[3]);
        Assert.Equal("drns.isoc.org.il", response.NameServers[4]);
        Assert.Equal("sns-pb.isc.org", response.NameServers[5]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Transfer Locked", response.DomainStatus[0]);

        Assert.Equal(49, response.FieldsParsed);
    }
}
