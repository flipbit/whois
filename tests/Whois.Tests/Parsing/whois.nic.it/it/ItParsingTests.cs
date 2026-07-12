using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.It.It
{
    public class ItParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ItParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "found.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("html.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ITnet s.r.l.", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 07, 01, 00, 02, 38, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1998, 08, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 06, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("HTML1-ITNIC", response.Registrant.RegistryId);
            Assert.Equal("HTML.it srl", response.Registrant.Name);
            Assert.Equal("HTML.it srl", response.Registrant.Organization);
            Assert.Equal(new DateTime(2007, 03, 01, 10, 28, 08, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2007, 03, 01, 10, 28, 08, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Viale Alessandrino, 595", response.Registrant.Address[0]);
            Assert.Equal("Roma", response.Registrant.Address[1]);
            Assert.Equal("00172", response.Registrant.Address[2]);
            Assert.Equal("RM", response.Registrant.Address[3]);
            Assert.Equal("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("MV943-ITNIC", response.AdminContact.RegistryId);
            Assert.Equal("Massimiliano Valente", response.AdminContact.Name);
            Assert.Equal(new DateTime(2006, 09, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2007, 03, 01, 07, 37, 14, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Viale Alessandrino, 595", response.AdminContact.Address[0]);
            Assert.Equal("Roma", response.AdminContact.Address[1]);
            Assert.Equal("00172", response.AdminContact.Address[2]);
            Assert.Equal("RM", response.AdminContact.Address[3]);
            Assert.Equal("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("MV943-ITNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Massimiliano Valente", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2006, 09, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2007, 03, 01, 07, 37, 14, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Viale Alessandrino, 595", response.TechnicalContact.Address[0]);
            Assert.Equal("Roma", response.TechnicalContact.Address[1]);
            Assert.Equal("00172", response.TechnicalContact.Address[2]);
            Assert.Equal("RM", response.TechnicalContact.Address[3]);
            Assert.Equal("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("dns.it.net", response.NameServers[0]);
            Assert.Equal("dns2.it.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(37, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contact_with_company_in_address()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "found_contact_with_company_in_address.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("ucicinemas.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Telnet s.r.l.", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 09, 01, 00, 02, 22, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2001, 10, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("UCII1-ITNIC", response.Registrant.RegistryId);
            Assert.Equal("UCI ITALIA Spa", response.Registrant.Name);
            Assert.Equal("UCI ITALIA Spa", response.Registrant.Organization);
            Assert.Equal(new DateTime(2007, 03, 01, 10, 27, 58, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2007, 03, 01, 10, 27, 58, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Via E. Fermi, 161", response.Registrant.Address[0]);
            Assert.Equal("Roma", response.Registrant.Address[1]);
            Assert.Equal("00146", response.Registrant.Address[2]);
            Assert.Equal("RM", response.Registrant.Address[3]);
            Assert.Equal("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("AARS1-ITNIC", response.AdminContact.RegistryId);
            Assert.Equal("Andrea Antonio Renato Stratta", response.AdminContact.Name);
            Assert.Equal(new DateTime(2006, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2007, 03, 01, 07, 48, 42, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("UCI Italia Srl", response.AdminContact.Address[0]);
            Assert.Equal("Via E. Fermi, 161", response.AdminContact.Address[1]);
            Assert.Equal("Roma", response.AdminContact.Address[2]);
            Assert.Equal("00146", response.AdminContact.Address[3]);
            Assert.Equal("RM", response.AdminContact.Address[4]);
            Assert.Equal("IT", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("AARS1-ITNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Andrea Antonio Renato Stratta", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2006, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2007, 03, 01, 07, 48, 42, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("UCI Italia Srl", response.TechnicalContact.Address[0]);
            Assert.Equal("Via E. Fermi, 161", response.TechnicalContact.Address[1]);
            Assert.Equal("Roma", response.TechnicalContact.Address[2]);
            Assert.Equal("00146", response.TechnicalContact.Address[3]);
            Assert.Equal("RM", response.TechnicalContact.Address[4]);
            Assert.Equal("IT", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns0.telnetwork.it", response.NameServers[0]);
            Assert.Equal("ns1.telnetwork.it", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(39, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_contact_with_organization()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "found_contact_with_organization.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

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
        public void Test_found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("imdb.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("NOM-IQ Ltd. Trading as Com Laude", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 10, 17, 01, 15, 20, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2000, 03, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("AMAZ26", response.Registrant.RegistryId);
            Assert.Equal("Domain Manager", response.Registrant.Name);
            Assert.Equal("Amazon Europe Holding Technologies SCS", response.Registrant.Organization);
            Assert.Equal(new DateTime(2008, 04, 21, 16, 07, 02, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2011, 02, 11, 14, 35, 52, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("65, boulevard Grande-Duchesse Charlotte", response.Registrant.Address[0]);
            Assert.Equal("Luxembourg City", response.Registrant.Address[1]);
            Assert.Equal("1311", response.Registrant.Address[2]);
            Assert.Equal("Luxembourg City", response.Registrant.Address[3]);
            Assert.Equal("LU", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("JK17042", response.AdminContact.RegistryId);
            Assert.Equal("Jocelyn Krabbenschmidt", response.AdminContact.Name);
            Assert.Equal("Amazon Europe Holding Technologies SCS", response.AdminContact.Organization);
            Assert.Equal(new DateTime(2008, 04, 21, 16, 07, 02, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2010, 12, 01, 11, 09, 07, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("65, boulevard Grande-Duchesse Charlotte", response.AdminContact.Address[0]);
            Assert.Equal("Luxembourg City", response.AdminContact.Address[1]);
            Assert.Equal("1311", response.AdminContact.Address[2]);
            Assert.Equal("LUXEMBOURG CITY", response.AdminContact.Address[3]);
            Assert.Equal("LU", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("DM18866", response.TechnicalContact.RegistryId);
            Assert.Equal("Dietrich Meyer", response.TechnicalContact.Name);
            Assert.Equal("Lovells", response.TechnicalContact.Organization);
            Assert.Equal(new DateTime(2007, 10, 16, 14, 25, 46, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2010, 12, 01, 11, 09, 07, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("6 Avenue Kleber", response.TechnicalContact.Address[0]);
            Assert.Equal("Paris", response.TechnicalContact.Address[1]);
            Assert.Equal("75116", response.TechnicalContact.Address[2]);
            Assert.Equal("PARIS", response.TechnicalContact.Address[3]);
            Assert.Equal("FR", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("pdns1.ultradns.net", response.NameServers[0]);
            Assert.Equal("pdns2.ultradns.net", response.NameServers[1]);
            Assert.Equal("pdns3.ultradns.org", response.NameServers[2]);
            Assert.Equal("pdns4.ultradns.org", response.NameServers[3]);
            Assert.Equal("pdns5.ultradns.info", response.NameServers[4]);
            Assert.Equal("pdns6.ultradns.co.uk", response.NameServers[5]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("autoRenewPeriod", response.DomainStatus[0]);

            Assert.Equal(43, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "not-found", "not_found.txt");
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
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_client.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("elle.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("INDOM", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 12, 21, 01, 03, 46, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1996, 01, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 12, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("HACH3", response.Registrant.RegistryId);
            Assert.Equal("HACHETTE FILIPACCHI PRESSE SA", response.Registrant.Name);
            Assert.Equal("HACHETTE FILIPACCHI PRESSE SA", response.Registrant.Organization);
            Assert.Equal(new DateTime(2007, 03, 01, 10, 30, 07, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2010, 06, 24, 10, 22, 43, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("149 rue Anatole France", response.Registrant.Address[0]);
            Assert.Equal("Levallois Perret Cedex", response.Registrant.Address[1]);
            Assert.Equal("92534", response.Registrant.Address[2]);
            Assert.Equal("FR", response.Registrant.Address[3]);
            Assert.Equal("FR", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("FS1840", response.AdminContact.RegistryId);
            Assert.Equal("Fabienne Sultan", response.AdminContact.Name);
            Assert.Equal(new DateTime(2003, 05, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2010, 07, 12, 15, 16, 48, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("149 rue Anatole France", response.AdminContact.Address[0]);
            Assert.Equal("92534 Levallois Perret Cedex", response.AdminContact.Address[1]);
            Assert.Equal("France", response.AdminContact.Address[2]);
            Assert.Equal("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("AT1480", response.TechnicalContact.RegistryId);
            Assert.Equal("Artful Tech", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2003, 05, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2010, 01, 21, 11, 25, 05, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("Artful", response.TechnicalContact.Address[0]);
            Assert.Equal("26 bis rue du Chene Germain", response.TechnicalContact.Address[1]);
            Assert.Equal("Cesson-Sevigne", response.TechnicalContact.Address[2]);
            Assert.Equal("35510", response.TechnicalContact.Address[3]);
            Assert.Equal("FR", response.TechnicalContact.Address[4]);
            Assert.Equal("FR", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.artful.net", response.NameServers[0]);
            Assert.Equal("ns2.artful.net", response.NameServers[1]);
            Assert.Equal("ns3.artful.net", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);

            Assert.Equal(38, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_graceperiod.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("hotellagioconda.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("SESTANTE s.r.l.", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 02, 12, 00, 30, 50, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2001, 09, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 02, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("SALG11-ITNIC", response.Registrant.RegistryId);
            Assert.Equal(@"S.A.L.G. S.r.l. Soc. Alberghi ""La Gioconda""", response.Registrant.Name);
            Assert.Equal(@"S.A.L.G. S.r.l. Soc. Alberghi ""La Gioconda""", response.Registrant.Organization);
            Assert.Equal(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Via Panzani 2", response.Registrant.Address[0]);
            Assert.Equal("Firenze", response.Registrant.Address[1]);
            Assert.Equal("50123", response.Registrant.Address[2]);
            Assert.Equal("FI", response.Registrant.Address[3]);
            Assert.Equal("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("TL6748-ITNIC", response.AdminContact.RegistryId);
            Assert.Equal("Tanja Lipira", response.AdminContact.Name);
            Assert.Equal(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Via Panzani 2", response.AdminContact.Address[0]);
            Assert.Equal("Firenze", response.AdminContact.Address[1]);
            Assert.Equal("50123", response.AdminContact.Address[2]);
            Assert.Equal("FI", response.AdminContact.Address[3]);
            Assert.Equal("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("HS3-ITNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("Hostmaster Sestante", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2005, 09, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2007, 03, 01, 07, 36, 55, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Via della Giustizia, 9", response.TechnicalContact.Address[0]);
            Assert.Equal("Fano", response.TechnicalContact.Address[1]);
            Assert.Equal("61032", response.TechnicalContact.Address[2]);
            Assert.Equal("PU", response.TechnicalContact.Address[3]);
            Assert.Equal("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.sestante.net", response.NameServers[0]);
            Assert.Equal("ns2.sestante.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("GRACE-PERIOD", response.DomainStatus[0]);

            Assert.Equal(37, response.FieldsParsed);
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
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_no_provider.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("chiara.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("CIM-MNT", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 06, 24, 23, 10, 26, 000, DateTimeKind.Utc), response.Updated);
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
            Assert.Equal("NO-PROVIDER", response.DomainStatus[0]);

            Assert.Equal(35, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "found_status_ok.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("decorstore.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Moviement s.r.l.", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 06, 07, 18, 50, 20, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 01, 24, 15, 40, 37, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 01, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("XYZ759", response.Registrant.RegistryId);
            Assert.Equal("3b srl", response.Registrant.Name);
            Assert.Equal("3b srl", response.Registrant.Organization);
            Assert.Equal(new DateTime(2008, 01, 24, 15, 40, 37, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2010, 05, 10, 11, 32, 32, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Via Marrucci, 43", response.Registrant.Address[0]);
            Assert.Equal("Cecina", response.Registrant.Address[1]);
            Assert.Equal("57023", response.Registrant.Address[2]);
            Assert.Equal("LI", response.Registrant.Address[3]);
            Assert.Equal("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("CB64898", response.AdminContact.RegistryId);
            Assert.Equal("Corrado Beggi", response.AdminContact.Name);
            Assert.Equal("3b srl", response.AdminContact.Organization);
            Assert.Equal(new DateTime(2008, 01, 24, 15, 40, 37, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2010, 05, 10, 11, 32, 53, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Via Marrucci, 43", response.AdminContact.Address[0]);
            Assert.Equal("Cecina", response.AdminContact.Address[1]);
            Assert.Equal("57023", response.AdminContact.Address[2]);
            Assert.Equal("LI", response.AdminContact.Address[3]);
            Assert.Equal("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("MVM0000034088", response.TechnicalContact.RegistryId);
            Assert.Equal("Moviement Srl", response.TechnicalContact.Name);
            Assert.Equal("Moviement Srl", response.TechnicalContact.Organization);
            Assert.Equal(new DateTime(2010, 06, 07, 17, 01, 37, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2010, 06, 29, 18, 35, 52, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Via San Mauro 7/9", response.TechnicalContact.Address[0]);
            Assert.Equal("Montegrotto Terme", response.TechnicalContact.Address[1]);
            Assert.Equal("35036", response.TechnicalContact.Address[2]);
            Assert.Equal("PD", response.TechnicalContact.Address[3]);
            Assert.Equal("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.clickcity.biz", response.NameServers[0]);
            Assert.Equal("ns2.clickcity.biz", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(39, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_ok_autorenew()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_ok_autorenew.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("venetamarmi.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Register.it s.p.a.", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 02, 05, 01, 48, 38, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1998, 07, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 02, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("VENE64", response.Registrant.RegistryId);
            Assert.Equal("Veneta Marmi Srl", response.Registrant.Name);
            Assert.Equal("Veneta Marmi Srl", response.Registrant.Organization);
            Assert.Equal(new DateTime(2007, 03, 01, 10, 33, 35, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2011, 01, 18, 11, 07, 43, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Via Pernisa,10", response.Registrant.Address[0]);
            Assert.Equal("Grezzana", response.Registrant.Address[1]);
            Assert.Equal("37023", response.Registrant.Address[2]);
            Assert.Equal("VR", response.Registrant.Address[3]);
            Assert.Equal("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("FR1005562", response.AdminContact.RegistryId);
            Assert.Equal("Ferrari Rino", response.AdminContact.Name);
            Assert.Equal("NA", response.AdminContact.Organization);
            Assert.Equal(new DateTime(2010, 11, 11, 16, 25, 37, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2011, 01, 18, 11, 07, 43, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Via Pernisa,10", response.AdminContact.Address[0]);
            Assert.Equal("Grezzana", response.AdminContact.Address[1]);
            Assert.Equal("37023", response.AdminContact.Address[2]);
            Assert.Equal("VR", response.AdminContact.Address[3]);
            Assert.Equal("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("2409-REGT", response.TechnicalContact.RegistryId);
            Assert.Equal("Technical Support", response.TechnicalContact.Name);
            Assert.Equal("Register.it S.p.A.", response.TechnicalContact.Organization);
            Assert.Equal(new DateTime(2009, 09, 28, 11, 01, 09, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2009, 09, 28, 11, 01, 09, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Via Montessori s/n", response.TechnicalContact.Address[0]);
            Assert.Equal("Bergamo", response.TechnicalContact.Address[1]);
            Assert.Equal("24126", response.TechnicalContact.Address[2]);
            Assert.Equal("BG", response.TechnicalContact.Address[3]);
            Assert.Equal("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.register.it", response.NameServers[0]);
            Assert.Equal("ns2.register.it", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(39, response.FieldsParsed);
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
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_pendingtransfer.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("alessandrofusco.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Serverplan s.r.l. Unipersonale", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 05, 02, 17, 26, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 06, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 06, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("AF7184", response.Registrant.RegistryId);
            Assert.Equal("Alessandro Fusco", response.Registrant.Name);
            Assert.Equal("Alessandro Fusco", response.Registrant.Organization);


             // AdminContact Details
            Assert.Equal("AF7184", response.AdminContact.RegistryId);
            Assert.Equal("Alessandro Fusco", response.AdminContact.Name);
            Assert.Equal("Alessandro Fusco", response.AdminContact.Organization);


             // TechnicalContact Details
            Assert.Equal("CDL148", response.TechnicalContact.RegistryId);
            Assert.Equal("Claudio De Luca", response.TechnicalContact.Name);
            Assert.Equal("Serverplan", response.TechnicalContact.Organization);
            Assert.Equal(new DateTime(2005, 07, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2010, 01, 28, 16, 10, 28, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Corso della Repubblica 171", response.TechnicalContact.Address[0]);
            Assert.Equal("Cassino", response.TechnicalContact.Address[1]);
            Assert.Equal("03043", response.TechnicalContact.Address[2]);
            Assert.Equal("FR", response.TechnicalContact.Address[3]);
            Assert.Equal("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns23.dnshighspeed.com", response.NameServers[0]);
            Assert.Equal("ns24.dnshighspeed.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("pendingTransfer", response.DomainStatus[0]);

            Assert.Equal(25, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_pendingtransfer_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_pendingtransfer_autorenewperiod.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("aversastore.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Euro Marketing SK SRO", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 10, 24, 02, 09, 47, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 10, 04, 07, 36, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 10, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("DUP200125359", response.Registrant.RegistryId);
            Assert.Equal("Francesco Fusco", response.Registrant.Name);
            Assert.Equal("Francesco Fusco", response.Registrant.Organization);


             // AdminContact Details
            Assert.Equal("DUP917904034", response.AdminContact.RegistryId);
            Assert.Equal("Francesco Fusco", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.Equal("DUP200125359", response.TechnicalContact.RegistryId);
            Assert.Equal("Francesco Fusco", response.TechnicalContact.Name);
            Assert.Equal("Francesco Fusco", response.TechnicalContact.Organization);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("mrddns001.misterdomain.eu", response.NameServers[0]);
            Assert.Equal("mrddns002.misterdomain.eu", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("pendingTransfer", response.DomainStatus[0]);

            Assert.Equal(17, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_pendingupdate()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_pendingupdate.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("fuoristradausato.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("PhoenixWeb s.n.c. di Marco Bianucci & C.", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 04, 30, 19, 24, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("AUTO2726", response.Registrant.RegistryId);
            Assert.Equal("Autonord S.r.l.", response.Registrant.Name);
            Assert.Equal("Autonord S.r.l.", response.Registrant.Organization);
            Assert.Equal(new DateTime(2007, 03, 01, 10, 50, 23, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2010, 05, 18, 13, 02, 40, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("via IX strada 21", response.Registrant.Address[0]);
            Assert.Equal("padova", response.Registrant.Address[1]);
            Assert.Equal("35129", response.Registrant.Address[2]);
            Assert.Equal("PD", response.Registrant.Address[3]);
            Assert.Equal("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("ER2146", response.AdminContact.RegistryId);
            Assert.Equal("Emilio Rampin", response.AdminContact.Name);
            Assert.Equal("Autonord S.r.l.", response.AdminContact.Organization);
            Assert.Equal(new DateTime(2006, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2010, 05, 18, 13, 03, 17, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("21", response.AdminContact.Address[0]);
            Assert.Equal("padova", response.AdminContact.Address[1]);
            Assert.Equal("35129", response.AdminContact.Address[2]);
            Assert.Equal("PD", response.AdminContact.Address[3]);
            Assert.Equal("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("MB8891", response.TechnicalContact.RegistryId);
            Assert.Equal("Marco Bianucci", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2005, 04, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2010, 05, 18, 13, 03, 26, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Via dei pioppi 2", response.TechnicalContact.Address[0]);
            Assert.Equal("Cesano Boscone", response.TechnicalContact.Address[1]);
            Assert.Equal("20090", response.TechnicalContact.Address[2]);
            Assert.Equal("MI", response.TechnicalContact.Address[3]);
            Assert.Equal("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns11.pegasodns.com", response.NameServers[0]);
            Assert.Equal("ns12.pegasodns.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("pendingUpdate", response.DomainStatus[0]);

            Assert.Equal(38, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_pendingupdate_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found", "other_status_pendingupdate_autorenewperiod.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.it/it/found/01", response.TemplateName);

            Assert.Equal("bunkerfilm.it", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Genesys Informatica s.r.l.", response.Registrar.Name);

            Assert.Equal(new DateTime(2012, 02, 28, 08, 51, 35, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("GIF-0000004711R", response.Registrant.RegistryId);
            Assert.Equal("FRANCESCO CACCHIANI2", response.Registrant.Name);
            Assert.Equal("FRANCESCO CACCHIANI", response.Registrant.Organization);
            Assert.Equal(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.Equal(new DateTime(2011, 04, 04, 16, 58, 43, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Via Ilio Barontini 1b", response.Registrant.Address[0]);
            Assert.Equal("Lastra a Signa", response.Registrant.Address[1]);
            Assert.Equal("50100", response.Registrant.Address[2]);
            Assert.Equal("FI", response.Registrant.Address[3]);
            Assert.Equal("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("GIF-0000004711R", response.AdminContact.RegistryId);
            Assert.Equal("FRANCESCO CACCHIANI2", response.AdminContact.Name);
            Assert.Equal("FRANCESCO CACCHIANI", response.AdminContact.Organization);
            Assert.Equal(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.Equal(new DateTime(2011, 04, 04, 16, 58, 43, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Via Ilio Barontini 1b", response.AdminContact.Address[0]);
            Assert.Equal("Lastra a Signa", response.AdminContact.Address[1]);
            Assert.Equal("50100", response.AdminContact.Address[2]);
            Assert.Equal("FI", response.AdminContact.Address[3]);
            Assert.Equal("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("GIF-0000004711R", response.TechnicalContact.RegistryId);
            Assert.Equal("FRANCESCO CACCHIANI2", response.TechnicalContact.Name);
            Assert.Equal("FRANCESCO CACCHIANI", response.TechnicalContact.Organization);
            Assert.Equal(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.Equal(new DateTime(2011, 04, 04, 16, 58, 43, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Via Ilio Barontini 1b", response.TechnicalContact.Address[0]);
            Assert.Equal("Lastra a Signa", response.TechnicalContact.Address[1]);
            Assert.Equal("50100", response.TechnicalContact.Address[2]);
            Assert.Equal("FI", response.TechnicalContact.Address[3]);
            Assert.Equal("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.asidev.net", response.NameServers[0]);
            Assert.Equal("ns2.asidev.net", response.NameServers[1]);
            Assert.Equal("ns3.asipec.com", response.NameServers[2]);
            Assert.Equal("ns4.asipec.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("pendingUpdate", response.DomainStatus[0]);

            Assert.Equal(41, response.FieldsParsed);
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
            var sample = SampleReader.Read("whois.nic.it", "it", "reserved", "reserved.txt");
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
            var sample = SampleReader.Read("whois.nic.it", "it", "not-found", "not_found_status_available.txt");
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
}
