using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.It.It;

public class ItParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ItParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "html.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("html.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 02, 06, 00, 49, 36, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1998, 08, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 01, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contact_with_company_in_address()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "ucicinemas.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("ucicinemas.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2025, 12, 14, 00, 47, 20, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 10, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 11, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contact_with_organization()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "google.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("google.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 06, 09, 23, 13, 34, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 12, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 04, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "imdb.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("imdb.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2025, 11, 01, 00, 44, 20, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2000, 03, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "not-found", "google-not-found.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("google-not-found.it", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("AVAILABLE", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_client()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "elle.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("elle.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2025, 11, 21, 11, 22, 31, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1996, 01, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 10, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_graceperiod()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "hotellagioconda.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("hotellagioconda.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2025, 09, 19, 10, 00, 18, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2025, 09, 19, 09, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 09, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_inactive_noregistrar()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_inactive_noregistrar.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotAssigned, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("tipassasubito.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("9NET s.r.l.", response.Registrar.Name);

        Assert.Equal(new DateTime(2011, 04, 13, 15, 41, 49, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 04, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("SIRI412", response.Registrant.RegistryId);
        Assert.Equal("SIRIS MEDIA FACTORY SRL", response.Registrant.Name);
        Assert.Equal("SIRIS MEDIA FACTORY SRL", response.Registrant.Organization);
        Assert.Equal(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.Registrant.Created);
        Assert.Equal(new DateTime(2011, 04, 13, 15, 24, 54, 000, DateTimeKind.Utc), response.Registrant.Updated);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Foro Buonaparte, 69", response.Registrant.Address[0]);
        Assert.Equal("Milano", response.Registrant.Address[1]);
        Assert.Equal("20121", response.Registrant.Address[2]);
        Assert.Equal("MI", response.Registrant.Address[3]);
        Assert.Equal("IT", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("CS31121", response.AdminContact.RegistryId);
        Assert.Equal("CLAUDIO SPADA", response.AdminContact.Name);
        Assert.Equal("SIRIS MEDIA FACTORY SRL", response.AdminContact.Organization);
        Assert.Equal(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.AdminContact.Created);
        Assert.Equal(new DateTime(2011, 04, 13, 15, 26, 01, 000, DateTimeKind.Utc), response.AdminContact.Updated);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Foro Buonaparte, 69", response.AdminContact.Address[0]);
        Assert.Equal("Milano", response.AdminContact.Address[1]);
        Assert.Equal("20121", response.AdminContact.Address[2]);
        Assert.Equal("MI", response.AdminContact.Address[3]);
        Assert.Equal("IT", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("CS31122", response.TechnicalContact.RegistryId);
        Assert.Equal("CLAUDIO SPADA", response.TechnicalContact.Name);
        Assert.Equal("SIRIS MEDIA FACTORY SRL", response.TechnicalContact.Organization);
        Assert.Equal(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
        Assert.Equal(new DateTime(2011, 04, 13, 15, 26, 17, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Foro Buonaparte, 69", response.TechnicalContact.Address[0]);
        Assert.Equal("Milano", response.TechnicalContact.Address[1]);
        Assert.Equal("20121", response.TechnicalContact.Address[2]);
        Assert.Equal("MI", response.TechnicalContact.Address[3]);
        Assert.Equal("IT", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.websolutions.it", response.NameServers[0]);
        Assert.Equal("ns2.websolutions.it", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("inactive", response.DomainStatus[0]);

        Assert.Equal(39, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_no_provider()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "chiara.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("chiara.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 03, 19, 00, 49, 20, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2012, 03, 01, 23, 47, 01, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 03, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_ok()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "decorstore.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("decorstore.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 01, 28, 00, 44, 43, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 01, 24, 15, 40, 37, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 01, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_ok_autorenew()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "venetamarmi.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("venetamarmi.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 02, 21, 00, 45, 33, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1998, 07, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 02, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_pendingdelete()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_pendingdelete.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.PendingDelete, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("chiara.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("CIM-MNT", response.Registrar.Name);

        Assert.Equal(new DateTime(2012, 02, 27, 00, 01, 44, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 12, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 12, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("INFO2436-ITNIC", response.Registrant.RegistryId);
        Assert.Equal("Infoplan di Giancarlo Abram", response.Registrant.Name);
        Assert.Equal(new DateTime(2007, 03, 01, 11, 04, 12, 000, DateTimeKind.Utc), response.Registrant.Created);
        Assert.Equal(new DateTime(2011, 02, 09, 11, 59, 46, 000, DateTimeKind.Utc), response.Registrant.Updated);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Via Gozzi 13", response.Registrant.Address[0]);
        Assert.Equal("Mestre", response.Registrant.Address[1]);
        Assert.Equal("30172", response.Registrant.Address[2]);
        Assert.Equal("VE", response.Registrant.Address[3]);
        Assert.Equal("IT", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("GA8285-ITNIC", response.AdminContact.RegistryId);
        Assert.Equal("Giancarlo Abram", response.AdminContact.Name);
        Assert.Equal(new DateTime(2007, 03, 01, 10, 26, 06, 000, DateTimeKind.Utc), response.AdminContact.Created);
        Assert.Equal(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.AdminContact.Updated);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("P.zza San Giovanni 14", response.AdminContact.Address[0]);
        Assert.Equal("Ronzone", response.AdminContact.Address[1]);
        Assert.Equal("38013", response.AdminContact.Address[2]);
        Assert.Equal("TN", response.AdminContact.Address[3]);
        Assert.Equal("IT", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("GA8285-ITNIC", response.TechnicalContact.RegistryId);
        Assert.Equal("Giancarlo Abram", response.TechnicalContact.Name);
        Assert.Equal(new DateTime(2007, 03, 01, 10, 26, 06, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
        Assert.Equal(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("P.zza San Giovanni 14", response.TechnicalContact.Address[0]);
        Assert.Equal("Ronzone", response.TechnicalContact.Address[1]);
        Assert.Equal("38013", response.TechnicalContact.Address[2]);
        Assert.Equal("TN", response.TechnicalContact.Address[3]);
        Assert.Equal("IT", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(1, response.NameServers.Count);
        Assert.Equal("ns.cim.it", response.NameServers[0]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("PENDING-DELETE", response.DomainStatus[0]);

        Assert.Equal(35, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_pendingdelete_pendingdelete()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_pendingdelete_pendingdelete.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.PendingDelete, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("cartucceweb.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("DominioFaiDaTe S.r.l.", response.Registrar.Name);

        Assert.Equal(new DateTime(2011, 06, 27, 12, 05, 12, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2007, 06, 07, 14, 48, 44, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 05, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("DFT-R-16249", response.Registrant.RegistryId);
        Assert.Equal("Jose Gregorio Chatila", response.Registrant.Name);
        Assert.Equal("CARTUCCEWEB DI CHATILA JOSE GREGORIO", response.Registrant.Organization);


        // AdminContact Details
        Assert.Equal("DUP008397314", response.AdminContact.RegistryId);
        Assert.Equal("JOSE GREGORIO CHATILA", response.AdminContact.Name);


        // TechnicalContact Details
        Assert.Equal("DUP753815370", response.TechnicalContact.RegistryId);
        Assert.Equal("Etesi s.r.l.", response.TechnicalContact.Name);
        Assert.Equal("www.ion.it - Italia on Net", response.TechnicalContact.Organization);
        Assert.Equal(new DateTime(2010, 05, 31, 00, 52, 08, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
        Assert.Equal(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Via Alloro, 8", response.TechnicalContact.Address[0]);
        Assert.Equal("Ribera", response.TechnicalContact.Address[1]);
        Assert.Equal("92016", response.TechnicalContact.Address[2]);
        Assert.Equal("AG", response.TechnicalContact.Address[3]);
        Assert.Equal("IT", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.dominiofaidate.com", response.NameServers[0]);
        Assert.Equal("ns2.dominiofaidate.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("pendingDelete", response.DomainStatus[0]);

        Assert.Equal(24, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_pendingdelete_redemptionperiod()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_pendingdelete_redemptionperiod.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.PendingDelete, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("concessionari-fiat.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Seeweb S.r.l.", response.Registrar.Name);

        Assert.Equal(new DateTime(2011, 02, 11, 15, 38, 31, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 02, 08, 22, 30, 04, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 02, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("THR1265664614", response.Registrant.RegistryId);
        Assert.Equal("Paolo Battistella", response.Registrant.Name);
        Assert.Equal("Paolo Battistella", response.Registrant.Organization);
        Assert.Equal(new DateTime(2010, 02, 08, 22, 30, 03, 000, DateTimeKind.Utc), response.Registrant.Created);
        Assert.Equal(new DateTime(2010, 07, 12, 15, 06, 50, 000, DateTimeKind.Utc), response.Registrant.Updated);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Via Donatello 7", response.Registrant.Address[0]);
        Assert.Equal("Prata Di Pordenone", response.Registrant.Address[1]);
        Assert.Equal("33080", response.Registrant.Address[2]);
        Assert.Equal("PN", response.Registrant.Address[3]);
        Assert.Equal("IT", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("THR1265664614", response.AdminContact.RegistryId);
        Assert.Equal("Paolo Battistella", response.AdminContact.Name);
        Assert.Equal("Paolo Battistella", response.AdminContact.Organization);
        Assert.Equal(new DateTime(2010, 02, 08, 22, 30, 03, 000, DateTimeKind.Utc), response.AdminContact.Created);
        Assert.Equal(new DateTime(2010, 07, 12, 15, 06, 50, 000, DateTimeKind.Utc), response.AdminContact.Updated);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Via Donatello 7", response.AdminContact.Address[0]);
        Assert.Equal("Prata Di Pordenone", response.AdminContact.Address[1]);
        Assert.Equal("33080", response.AdminContact.Address[2]);
        Assert.Equal("PN", response.AdminContact.Address[3]);
        Assert.Equal("IT", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("TOPHOST", response.TechnicalContact.RegistryId);
        Assert.Equal("Unita' Tecnica Tophost", response.TechnicalContact.Name);
        Assert.Equal("Tophost srl", response.TechnicalContact.Organization);
        Assert.Equal(new DateTime(2009, 09, 28, 11, 25, 11, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
        Assert.Equal(new DateTime(2009, 09, 28, 11, 25, 11, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("P.zza della liberta' 10", response.TechnicalContact.Address[0]);
        Assert.Equal("Roma", response.TechnicalContact.Address[1]);
        Assert.Equal("00195", response.TechnicalContact.Address[2]);
        Assert.Equal("RM", response.TechnicalContact.Address[3]);
        Assert.Equal("IT", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.th.seeweb.it", response.NameServers[0]);
        Assert.Equal("ns2.th.seeweb.it", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("pendingDelete", response.DomainStatus[0]);

        Assert.Equal(39, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_pendingtransfer()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "alessandrofusco.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("alessandrofusco.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2025, 12, 22, 00, 44, 42, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2019, 12, 06, 15, 25, 24, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 12, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_pendingtransfer_autorenewperiod()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "aversastore.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("aversastore.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 02, 09, 12, 43, 25, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2025, 08, 06, 16, 00, 04, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 08, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_pendingupdate()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "fuoristradausato.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("fuoristradausato.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2025, 12, 02, 00, 48, 40, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2012, 11, 16, 08, 21, 06, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 11, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_pendingupdate_autorenewperiod()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "bunkerfilm.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("bunkerfilm.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Equal(new DateTime(2026, 02, 07, 00, 52, 16, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2013, 01, 22, 16, 25, 46, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 01, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_redemption_no_provider()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_redemption_no_provider.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Redemption, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("pilotielicottero.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("SEEWEB-MNT", response.Registrar.Name);

        Assert.Equal(new DateTime(2011, 03, 19, 00, 01, 06, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2002, 01, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 03, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("PA424-ITNIC", response.Registrant.RegistryId);
        Assert.Equal("Pozzo Arturo", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("PA424-ITNIC", response.AdminContact.RegistryId);
        Assert.Equal("Pozzo Arturo", response.AdminContact.Name);


        // TechnicalContact Details
        Assert.Equal("AB141417", response.TechnicalContact.RegistryId);
        Assert.Equal("Antonio Baldassarra", response.TechnicalContact.Name);
        Assert.Equal(new DateTime(2007, 03, 01, 10, 25, 57, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
        Assert.Equal(new DateTime(2010, 07, 15, 09, 28, 14, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("C.so Lazio 9/a", response.TechnicalContact.Address[0]);
        Assert.Equal("Frosinone", response.TechnicalContact.Address[1]);
        Assert.Equal("03100", response.TechnicalContact.Address[2]);
        Assert.Equal("FR", response.TechnicalContact.Address[3]);
        Assert.Equal("IT", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("dns.seeweb.it", response.NameServers[0]);
        Assert.Equal("dns2.seeweb.it", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("REDEMPTION-NO-PROVIDER", response.DomainStatus[0]);

        Assert.Equal(22, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "reserved", "comunediroccaromana.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("comunediroccaromana.it", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("RESERVED", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_unassignable()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_unassignable.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("la.it", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("UNASSIGNABLE", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_technical_contact()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "found_technical_contact.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        AssertWriter.Write(response);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("google.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Register.it s.p.a.", response.Registrar.Name);

        Assert.Equal(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 12, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2009, 11, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("GOOG175-ITNIC", response.Registrant.RegistryId);
        Assert.Equal("Google Ireland Holdings", response.Registrant.Name);
        Assert.Equal(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Registrant.Created);
        Assert.Equal(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Registrant.Updated);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("30 Herbert Street", response.Registrant.Address[0]);
        Assert.Equal("Dublin", response.Registrant.Address[1]);
        Assert.Equal("2", response.Registrant.Address[2]);
        Assert.Equal("IE", response.Registrant.Address[3]);
        Assert.Equal("IE", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("TT4277-ITNIC", response.AdminContact.RegistryId);
        Assert.Equal("Tsao Tu", response.AdminContact.Name);
        Assert.Equal(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.AdminContact.Created);
        Assert.Equal(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.AdminContact.Updated);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("30 Herbert Street", response.AdminContact.Address[0]);
        Assert.Equal("Dublin", response.AdminContact.Address[1]);
        Assert.Equal("2", response.AdminContact.Address[2]);
        Assert.Equal("IE", response.AdminContact.Address[3]);
        Assert.Equal("IE", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("TS7016-ITNIC", response.TechnicalContact.RegistryId);
        Assert.Equal("Technical Services", response.TechnicalContact.Name);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns4.google.com", response.NameServers[1]);
        Assert.Equal("ns2.google.com", response.NameServers[2]);
        Assert.Equal("ns3.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVE", response.DomainStatus[0]);

        Assert.Equal(31, response.FieldsParsed);
    }

    [Fact]
    public void Test_unavailable()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "unavailable", "unavailable.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/unavailable/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found_status_available()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "not-found", "u34jedzcq.it.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.it", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("AVAILABLE", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("google.it", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor International Limited", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 12, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 04, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("DUP430692088", response.Registrant.RegistryId);
        Assert.Equal("Google Ireland Holdings", response.Registrant.Name);
        Assert.Equal("Google Ireland Holdings", response.Registrant.Organization);
        Assert.Equal(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.Registrant.Created);
        Assert.Equal(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.Registrant.Updated);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("70 Sir John Rogersons Quay", response.Registrant.Address[0]);
        Assert.Equal("Dublin", response.Registrant.Address[1]);
        Assert.Equal("2", response.Registrant.Address[2]);
        Assert.Equal("IE", response.Registrant.Address[3]);
        Assert.Equal("IE", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("DUP142437129", response.AdminContact.RegistryId);
        Assert.Equal("Tsao Tu", response.AdminContact.Name);
        Assert.Equal("Tu Tsao", response.AdminContact.Organization);
        Assert.Equal(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.AdminContact.Created);
        Assert.Equal(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.AdminContact.Updated);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("70 Sir John Rogersons Quay", response.AdminContact.Address[0]);
        Assert.Equal("Dublin", response.AdminContact.Address[1]);
        Assert.Equal("2", response.AdminContact.Address[2]);
        Assert.Equal("IE", response.AdminContact.Address[3]);
        Assert.Equal("IE", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("DUP430692088", response.TechnicalContact.RegistryId);
        Assert.Equal("Google Ireland Holdings", response.TechnicalContact.Name);
        Assert.Equal("Google Ireland Holdings", response.TechnicalContact.Organization);
        Assert.Equal(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
        Assert.Equal(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("70 Sir John Rogersons Quay", response.TechnicalContact.Address[0]);
        Assert.Equal("Dublin", response.TechnicalContact.Address[1]);
        Assert.Equal("2", response.TechnicalContact.Address[2]);
        Assert.Equal("IE", response.TechnicalContact.Address[3]);
        Assert.Equal("IE", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns4.google.com", response.NameServers[1]);
        Assert.Equal("ns2.google.com", response.NameServers[2]);
        Assert.Equal("ns3.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(41, response.FieldsParsed);
    }

    [Fact]
    public void Test_unavailable_status_unavailable()
    {
        var sample = SampleReader.Read("whois.nic.it", "it", "unavailable", "unavailable_status_unavailable.txt");
        var response = parser.Parse("whois.nic.it", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

        Assert.Equal("la-unavailable.it", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("UNASSIGNABLE", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }
}
