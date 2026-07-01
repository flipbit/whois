using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.It.It
{
    [TestFixture]
    public class ItParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("html.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ITnet s.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 07, 01, 00, 02, 38, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1998, 08, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 06, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("HTML1-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual("HTML.it srl", response.Registrant.Name);
            Assert.AreEqual("HTML.it srl", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 28, 08, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 28, 08, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Viale Alessandrino, 595", response.Registrant.Address[0]);
            Assert.AreEqual("Roma", response.Registrant.Address[1]);
            Assert.AreEqual("00172", response.Registrant.Address[2]);
            Assert.AreEqual("RM", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("MV943-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Massimiliano Valente", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2006, 09, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2007, 03, 01, 07, 37, 14, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Viale Alessandrino, 595", response.AdminContact.Address[0]);
            Assert.AreEqual("Roma", response.AdminContact.Address[1]);
            Assert.AreEqual("00172", response.AdminContact.Address[2]);
            Assert.AreEqual("RM", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("MV943-ITNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Massimiliano Valente", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2006, 09, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2007, 03, 01, 07, 37, 14, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Viale Alessandrino, 595", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Roma", response.TechnicalContact.Address[1]);
            Assert.AreEqual("00172", response.TechnicalContact.Address[2]);
            Assert.AreEqual("RM", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("dns.it.net", response.NameServers[0]);
            Assert.AreEqual("dns2.it.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(37, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_with_company_in_address()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_contact_with_company_in_address.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("ucicinemas.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Telnet s.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 09, 01, 00, 02, 22, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 10, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("UCII1-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual("UCI ITALIA Spa", response.Registrant.Name);
            Assert.AreEqual("UCI ITALIA Spa", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 27, 58, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 27, 58, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via E. Fermi, 161", response.Registrant.Address[0]);
            Assert.AreEqual("Roma", response.Registrant.Address[1]);
            Assert.AreEqual("00146", response.Registrant.Address[2]);
            Assert.AreEqual("RM", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("AARS1-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Andrea Antonio Renato Stratta", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2006, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2007, 03, 01, 07, 48, 42, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("UCI Italia Srl", response.AdminContact.Address[0]);
            Assert.AreEqual("Via E. Fermi, 161", response.AdminContact.Address[1]);
            Assert.AreEqual("Roma", response.AdminContact.Address[2]);
            Assert.AreEqual("00146", response.AdminContact.Address[3]);
            Assert.AreEqual("RM", response.AdminContact.Address[4]);
            Assert.AreEqual("IT", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("AARS1-ITNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Andrea Antonio Renato Stratta", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2006, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2007, 03, 01, 07, 48, 42, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("UCI Italia Srl", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Via E. Fermi, 161", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Roma", response.TechnicalContact.Address[2]);
            Assert.AreEqual("00146", response.TechnicalContact.Address[3]);
            Assert.AreEqual("RM", response.TechnicalContact.Address[4]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns0.telnetwork.it", response.NameServers[0]);
            Assert.AreEqual("ns1.telnetwork.it", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_found_contact_with_organization()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_contact_with_organization.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("google.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Register.it s.p.a.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 12, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2009, 11, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOG175-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Google Ireland Holdings", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("30 Herbert Street", response.Registrant.Address[0]);
            Assert.AreEqual("Dublin", response.Registrant.Address[1]);
            Assert.AreEqual("2", response.Registrant.Address[2]);
            Assert.AreEqual("IE", response.Registrant.Address[3]);
            Assert.AreEqual("IE", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("TT4277-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Tsao Tu", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("30 Herbert Street", response.AdminContact.Address[0]);
            Assert.AreEqual("Dublin", response.AdminContact.Address[1]);
            Assert.AreEqual("2", response.AdminContact.Address[2]);
            Assert.AreEqual("IE", response.AdminContact.Address[3]);
            Assert.AreEqual("IE", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("TS7016-ITNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Technical Services", response.TechnicalContact.Name);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns4.google.com", response.NameServers[1]);
            Assert.AreEqual("ns2.google.com", response.NameServers[2]);
            Assert.AreEqual("ns3.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(31, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("imdb.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NOM-IQ Ltd. Trading as Com Laude", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 10, 17, 01, 15, 20, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 03, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("AMAZ26", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Manager", response.Registrant.Name);
            Assert.AreEqual("Amazon Europe Holding Technologies SCS", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2008, 04, 21, 16, 07, 02, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2011, 02, 11, 14, 35, 52, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("65, boulevard Grande-Duchesse Charlotte", response.Registrant.Address[0]);
            Assert.AreEqual("Luxembourg City", response.Registrant.Address[1]);
            Assert.AreEqual("1311", response.Registrant.Address[2]);
            Assert.AreEqual("Luxembourg City", response.Registrant.Address[3]);
            Assert.AreEqual("LU", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("JK17042", response.AdminContact.RegistryId);
            Assert.AreEqual("Jocelyn Krabbenschmidt", response.AdminContact.Name);
            Assert.AreEqual("Amazon Europe Holding Technologies SCS", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2008, 04, 21, 16, 07, 02, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2010, 12, 01, 11, 09, 07, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("65, boulevard Grande-Duchesse Charlotte", response.AdminContact.Address[0]);
            Assert.AreEqual("Luxembourg City", response.AdminContact.Address[1]);
            Assert.AreEqual("1311", response.AdminContact.Address[2]);
            Assert.AreEqual("LUXEMBOURG CITY", response.AdminContact.Address[3]);
            Assert.AreEqual("LU", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("DM18866", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Dietrich Meyer", response.TechnicalContact.Name);
            Assert.AreEqual("Lovells", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2007, 10, 16, 14, 25, 46, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 12, 01, 11, 09, 07, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("6 Avenue Kleber", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Paris", response.TechnicalContact.Address[1]);
            Assert.AreEqual("75116", response.TechnicalContact.Address[2]);
            Assert.AreEqual("PARIS", response.TechnicalContact.Address[3]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("pdns1.ultradns.net", response.NameServers[0]);
            Assert.AreEqual("pdns2.ultradns.net", response.NameServers[1]);
            Assert.AreEqual("pdns3.ultradns.org", response.NameServers[2]);
            Assert.AreEqual("pdns4.ultradns.org", response.NameServers[3]);
            Assert.AreEqual("pdns5.ultradns.info", response.NameServers[4]);
            Assert.AreEqual("pdns6.ultradns.co.uk", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("autoRenewPeriod", response.DomainStatus[0]);

            Assert.AreEqual(43, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "not_found.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("google.it", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("AVAILABLE", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_client()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_client.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("elle.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("INDOM", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 12, 21, 01, 03, 46, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 01, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 12, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("HACH3", response.Registrant.RegistryId);
            Assert.AreEqual("HACHETTE FILIPACCHI PRESSE SA", response.Registrant.Name);
            Assert.AreEqual("HACHETTE FILIPACCHI PRESSE SA", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 30, 07, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2010, 06, 24, 10, 22, 43, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("149 rue Anatole France", response.Registrant.Address[0]);
            Assert.AreEqual("Levallois Perret Cedex", response.Registrant.Address[1]);
            Assert.AreEqual("92534", response.Registrant.Address[2]);
            Assert.AreEqual("FR", response.Registrant.Address[3]);
            Assert.AreEqual("FR", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("FS1840", response.AdminContact.RegistryId);
            Assert.AreEqual("Fabienne Sultan", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2003, 05, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 16, 48, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("149 rue Anatole France", response.AdminContact.Address[0]);
            Assert.AreEqual("92534 Levallois Perret Cedex", response.AdminContact.Address[1]);
            Assert.AreEqual("France", response.AdminContact.Address[2]);
            Assert.AreEqual("FR", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("AT1480", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Artful Tech", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2003, 05, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 01, 21, 11, 25, 05, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Artful", response.TechnicalContact.Address[0]);
            Assert.AreEqual("26 bis rue du Chene Germain", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Cesson-Sevigne", response.TechnicalContact.Address[2]);
            Assert.AreEqual("35510", response.TechnicalContact.Address[3]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[4]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.artful.net", response.NameServers[0]);
            Assert.AreEqual("ns2.artful.net", response.NameServers[1]);
            Assert.AreEqual("ns3.artful.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[0]);

            Assert.AreEqual(38, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_graceperiod.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("hotellagioconda.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("SESTANTE s.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 02, 12, 00, 30, 50, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 09, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 02, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("SALG11-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual(@"S.A.L.G. S.r.l. Soc. Alberghi ""La Gioconda""", response.Registrant.Name);
            Assert.AreEqual(@"S.A.L.G. S.r.l. Soc. Alberghi ""La Gioconda""", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Panzani 2", response.Registrant.Address[0]);
            Assert.AreEqual("Firenze", response.Registrant.Address[1]);
            Assert.AreEqual("50123", response.Registrant.Address[2]);
            Assert.AreEqual("FI", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("TL6748-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Tanja Lipira", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2008, 02, 11, 12, 18, 47, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Via Panzani 2", response.AdminContact.Address[0]);
            Assert.AreEqual("Firenze", response.AdminContact.Address[1]);
            Assert.AreEqual("50123", response.AdminContact.Address[2]);
            Assert.AreEqual("FI", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("HS3-ITNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hostmaster Sestante", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2005, 09, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2007, 03, 01, 07, 36, 55, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via della Giustizia, 9", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Fano", response.TechnicalContact.Address[1]);
            Assert.AreEqual("61032", response.TechnicalContact.Address[2]);
            Assert.AreEqual("PU", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.sestante.net", response.NameServers[0]);
            Assert.AreEqual("ns2.sestante.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("GRACE-PERIOD", response.DomainStatus[0]);

            Assert.AreEqual(37, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_inactive_noregistrar()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_inactive_noregistrar.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotAssigned, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("tipassasubito.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("9NET s.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 04, 13, 15, 41, 49, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 04, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("SIRI412", response.Registrant.RegistryId);
            Assert.AreEqual("SIRIS MEDIA FACTORY SRL", response.Registrant.Name);
            Assert.AreEqual("SIRIS MEDIA FACTORY SRL", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2011, 04, 13, 15, 24, 54, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Foro Buonaparte, 69", response.Registrant.Address[0]);
            Assert.AreEqual("Milano", response.Registrant.Address[1]);
            Assert.AreEqual("20121", response.Registrant.Address[2]);
            Assert.AreEqual("MI", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("CS31121", response.AdminContact.RegistryId);
            Assert.AreEqual("CLAUDIO SPADA", response.AdminContact.Name);
            Assert.AreEqual("SIRIS MEDIA FACTORY SRL", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2011, 04, 13, 15, 26, 01, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Foro Buonaparte, 69", response.AdminContact.Address[0]);
            Assert.AreEqual("Milano", response.AdminContact.Address[1]);
            Assert.AreEqual("20121", response.AdminContact.Address[2]);
            Assert.AreEqual("MI", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("CS31122", response.TechnicalContact.RegistryId);
            Assert.AreEqual("CLAUDIO SPADA", response.TechnicalContact.Name);
            Assert.AreEqual("SIRIS MEDIA FACTORY SRL", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2008, 04, 02, 16, 20, 50, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2011, 04, 13, 15, 26, 17, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Foro Buonaparte, 69", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Milano", response.TechnicalContact.Address[1]);
            Assert.AreEqual("20121", response.TechnicalContact.Address[2]);
            Assert.AreEqual("MI", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.websolutions.it", response.NameServers[0]);
            Assert.AreEqual("ns2.websolutions.it", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("inactive", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_no_provider()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_no_provider.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("chiara.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("CIM-MNT", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 06, 24, 23, 10, 26, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 12, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 12, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("INFO2436-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Infoplan di Giancarlo Abram", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2007, 03, 01, 11, 04, 12, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2011, 02, 09, 11, 59, 46, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Gozzi 13", response.Registrant.Address[0]);
            Assert.AreEqual("Mestre", response.Registrant.Address[1]);
            Assert.AreEqual("30172", response.Registrant.Address[2]);
            Assert.AreEqual("VE", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("GA8285-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Giancarlo Abram", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 26, 06, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("P.zza San Giovanni 14", response.AdminContact.Address[0]);
            Assert.AreEqual("Ronzone", response.AdminContact.Address[1]);
            Assert.AreEqual("38013", response.AdminContact.Address[2]);
            Assert.AreEqual("TN", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("GA8285-ITNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Giancarlo Abram", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 26, 06, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("P.zza San Giovanni 14", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Ronzone", response.TechnicalContact.Address[1]);
            Assert.AreEqual("38013", response.TechnicalContact.Address[2]);
            Assert.AreEqual("TN", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns.cim.it", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("NO-PROVIDER", response.DomainStatus[0]);

            Assert.AreEqual(35, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_ok.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("decorstore.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Moviement s.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 06, 07, 18, 50, 20, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 01, 24, 15, 40, 37, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 01, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("XYZ759", response.Registrant.RegistryId);
            Assert.AreEqual("3b srl", response.Registrant.Name);
            Assert.AreEqual("3b srl", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2008, 01, 24, 15, 40, 37, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2010, 05, 10, 11, 32, 32, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Marrucci, 43", response.Registrant.Address[0]);
            Assert.AreEqual("Cecina", response.Registrant.Address[1]);
            Assert.AreEqual("57023", response.Registrant.Address[2]);
            Assert.AreEqual("LI", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("CB64898", response.AdminContact.RegistryId);
            Assert.AreEqual("Corrado Beggi", response.AdminContact.Name);
            Assert.AreEqual("3b srl", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2008, 01, 24, 15, 40, 37, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2010, 05, 10, 11, 32, 53, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Via Marrucci, 43", response.AdminContact.Address[0]);
            Assert.AreEqual("Cecina", response.AdminContact.Address[1]);
            Assert.AreEqual("57023", response.AdminContact.Address[2]);
            Assert.AreEqual("LI", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("MVM0000034088", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Moviement Srl", response.TechnicalContact.Name);
            Assert.AreEqual("Moviement Srl", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2010, 06, 07, 17, 01, 37, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 06, 29, 18, 35, 52, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via San Mauro 7/9", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Montegrotto Terme", response.TechnicalContact.Address[1]);
            Assert.AreEqual("35036", response.TechnicalContact.Address[2]);
            Assert.AreEqual("PD", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.clickcity.biz", response.NameServers[0]);
            Assert.AreEqual("ns2.clickcity.biz", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_ok_autorenew()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_ok_autorenew.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("venetamarmi.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Register.it s.p.a.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 02, 05, 01, 48, 38, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1998, 07, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 02, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("VENE64", response.Registrant.RegistryId);
            Assert.AreEqual("Veneta Marmi Srl", response.Registrant.Name);
            Assert.AreEqual("Veneta Marmi Srl", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 33, 35, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2011, 01, 18, 11, 07, 43, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Pernisa,10", response.Registrant.Address[0]);
            Assert.AreEqual("Grezzana", response.Registrant.Address[1]);
            Assert.AreEqual("37023", response.Registrant.Address[2]);
            Assert.AreEqual("VR", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("FR1005562", response.AdminContact.RegistryId);
            Assert.AreEqual("Ferrari Rino", response.AdminContact.Name);
            Assert.AreEqual("NA", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2010, 11, 11, 16, 25, 37, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2011, 01, 18, 11, 07, 43, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Via Pernisa,10", response.AdminContact.Address[0]);
            Assert.AreEqual("Grezzana", response.AdminContact.Address[1]);
            Assert.AreEqual("37023", response.AdminContact.Address[2]);
            Assert.AreEqual("VR", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("2409-REGT", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Technical Support", response.TechnicalContact.Name);
            Assert.AreEqual("Register.it S.p.A.", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2009, 09, 28, 11, 01, 09, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2009, 09, 28, 11, 01, 09, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via Montessori s/n", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Bergamo", response.TechnicalContact.Address[1]);
            Assert.AreEqual("24126", response.TechnicalContact.Address[2]);
            Assert.AreEqual("BG", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.register.it", response.NameServers[0]);
            Assert.AreEqual("ns2.register.it", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_pendingdelete()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("chiara.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("CIM-MNT", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 02, 27, 00, 01, 44, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 12, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 12, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("INFO2436-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Infoplan di Giancarlo Abram", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2007, 03, 01, 11, 04, 12, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2011, 02, 09, 11, 59, 46, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Gozzi 13", response.Registrant.Address[0]);
            Assert.AreEqual("Mestre", response.Registrant.Address[1]);
            Assert.AreEqual("30172", response.Registrant.Address[2]);
            Assert.AreEqual("VE", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("GA8285-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Giancarlo Abram", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 26, 06, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("P.zza San Giovanni 14", response.AdminContact.Address[0]);
            Assert.AreEqual("Ronzone", response.AdminContact.Address[1]);
            Assert.AreEqual("38013", response.AdminContact.Address[2]);
            Assert.AreEqual("TN", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("GA8285-ITNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Giancarlo Abram", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 26, 06, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("P.zza San Giovanni 14", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Ronzone", response.TechnicalContact.Address[1]);
            Assert.AreEqual("38013", response.TechnicalContact.Address[2]);
            Assert.AreEqual("TN", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns.cim.it", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("PENDING-DELETE", response.DomainStatus[0]);

            Assert.AreEqual(35, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_pendingdelete_pendingdelete()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete_pendingdelete.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("cartucceweb.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("DominioFaiDaTe S.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 06, 27, 12, 05, 12, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 06, 07, 14, 48, 44, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 05, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DFT-R-16249", response.Registrant.RegistryId);
            Assert.AreEqual("Jose Gregorio Chatila", response.Registrant.Name);
            Assert.AreEqual("CARTUCCEWEB DI CHATILA JOSE GREGORIO", response.Registrant.Organization);


             // AdminContact Details
            Assert.AreEqual("DUP008397314", response.AdminContact.RegistryId);
            Assert.AreEqual("JOSE GREGORIO CHATILA", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.AreEqual("DUP753815370", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Etesi s.r.l.", response.TechnicalContact.Name);
            Assert.AreEqual("www.ion.it - Italia on Net", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2010, 05, 31, 00, 52, 08, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 25, 22, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via Alloro, 8", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Ribera", response.TechnicalContact.Address[1]);
            Assert.AreEqual("92016", response.TechnicalContact.Address[2]);
            Assert.AreEqual("AG", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.dominiofaidate.com", response.NameServers[0]);
            Assert.AreEqual("ns2.dominiofaidate.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingDelete", response.DomainStatus[0]);

            Assert.AreEqual(24, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_pendingdelete_redemptionperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete_redemptionperiod.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("concessionari-fiat.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Seeweb S.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 02, 11, 15, 38, 31, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 02, 08, 22, 30, 04, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 02, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("THR1265664614", response.Registrant.RegistryId);
            Assert.AreEqual("Paolo Battistella", response.Registrant.Name);
            Assert.AreEqual("Paolo Battistella", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2010, 02, 08, 22, 30, 03, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 06, 50, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Donatello 7", response.Registrant.Address[0]);
            Assert.AreEqual("Prata Di Pordenone", response.Registrant.Address[1]);
            Assert.AreEqual("33080", response.Registrant.Address[2]);
            Assert.AreEqual("PN", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("THR1265664614", response.AdminContact.RegistryId);
            Assert.AreEqual("Paolo Battistella", response.AdminContact.Name);
            Assert.AreEqual("Paolo Battistella", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2010, 02, 08, 22, 30, 03, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 12, 15, 06, 50, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Via Donatello 7", response.AdminContact.Address[0]);
            Assert.AreEqual("Prata Di Pordenone", response.AdminContact.Address[1]);
            Assert.AreEqual("33080", response.AdminContact.Address[2]);
            Assert.AreEqual("PN", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("TOPHOST", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Unita' Tecnica Tophost", response.TechnicalContact.Name);
            Assert.AreEqual("Tophost srl", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2009, 09, 28, 11, 25, 11, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2009, 09, 28, 11, 25, 11, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("P.zza della liberta' 10", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Roma", response.TechnicalContact.Address[1]);
            Assert.AreEqual("00195", response.TechnicalContact.Address[2]);
            Assert.AreEqual("RM", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.th.seeweb.it", response.NameServers[0]);
            Assert.AreEqual("ns2.th.seeweb.it", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingDelete", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_pendingtransfer()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingtransfer.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("alessandrofusco.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Serverplan s.r.l. Unipersonale", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 05, 02, 17, 26, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 06, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 06, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("AF7184", response.Registrant.RegistryId);
            Assert.AreEqual("Alessandro Fusco", response.Registrant.Name);
            Assert.AreEqual("Alessandro Fusco", response.Registrant.Organization);


             // AdminContact Details
            Assert.AreEqual("AF7184", response.AdminContact.RegistryId);
            Assert.AreEqual("Alessandro Fusco", response.AdminContact.Name);
            Assert.AreEqual("Alessandro Fusco", response.AdminContact.Organization);


             // TechnicalContact Details
            Assert.AreEqual("CDL148", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Claudio De Luca", response.TechnicalContact.Name);
            Assert.AreEqual("Serverplan", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2005, 07, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 01, 28, 16, 10, 28, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Corso della Repubblica 171", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Cassino", response.TechnicalContact.Address[1]);
            Assert.AreEqual("03043", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns23.dnshighspeed.com", response.NameServers[0]);
            Assert.AreEqual("ns24.dnshighspeed.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingTransfer", response.DomainStatus[0]);

            Assert.AreEqual(25, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_pendingtransfer_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingtransfer_autorenewperiod.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("aversastore.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Euro Marketing SK SRO", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 10, 24, 02, 09, 47, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 10, 04, 07, 36, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 10, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DUP200125359", response.Registrant.RegistryId);
            Assert.AreEqual("Francesco Fusco", response.Registrant.Name);
            Assert.AreEqual("Francesco Fusco", response.Registrant.Organization);


             // AdminContact Details
            Assert.AreEqual("DUP917904034", response.AdminContact.RegistryId);
            Assert.AreEqual("Francesco Fusco", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.AreEqual("DUP200125359", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Francesco Fusco", response.TechnicalContact.Name);
            Assert.AreEqual("Francesco Fusco", response.TechnicalContact.Organization);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("mrddns001.misterdomain.eu", response.NameServers[0]);
            Assert.AreEqual("mrddns002.misterdomain.eu", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingTransfer", response.DomainStatus[0]);

            Assert.AreEqual(17, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_pendingupdate()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingupdate.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("fuoristradausato.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("PhoenixWeb s.n.c. di Marco Bianucci & C.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 04, 30, 19, 24, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("AUTO2726", response.Registrant.RegistryId);
            Assert.AreEqual("Autonord S.r.l.", response.Registrant.Name);
            Assert.AreEqual("Autonord S.r.l.", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 50, 23, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2010, 05, 18, 13, 02, 40, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("via IX strada 21", response.Registrant.Address[0]);
            Assert.AreEqual("padova", response.Registrant.Address[1]);
            Assert.AreEqual("35129", response.Registrant.Address[2]);
            Assert.AreEqual("PD", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("ER2146", response.AdminContact.RegistryId);
            Assert.AreEqual("Emilio Rampin", response.AdminContact.Name);
            Assert.AreEqual("Autonord S.r.l.", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2006, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2010, 05, 18, 13, 03, 17, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("21", response.AdminContact.Address[0]);
            Assert.AreEqual("padova", response.AdminContact.Address[1]);
            Assert.AreEqual("35129", response.AdminContact.Address[2]);
            Assert.AreEqual("PD", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("MB8891", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Marco Bianucci", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2005, 04, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 05, 18, 13, 03, 26, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via dei pioppi 2", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Cesano Boscone", response.TechnicalContact.Address[1]);
            Assert.AreEqual("20090", response.TechnicalContact.Address[2]);
            Assert.AreEqual("MI", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns11.pegasodns.com", response.NameServers[0]);
            Assert.AreEqual("ns12.pegasodns.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingUpdate", response.DomainStatus[0]);

            Assert.AreEqual(38, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_pendingupdate_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingupdate_autorenewperiod.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("bunkerfilm.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Genesys Informatica s.r.l.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 02, 28, 08, 51, 35, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GIF-0000004711R", response.Registrant.RegistryId);
            Assert.AreEqual("FRANCESCO CACCHIANI2", response.Registrant.Name);
            Assert.AreEqual("FRANCESCO CACCHIANI", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2011, 04, 04, 16, 58, 43, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Ilio Barontini 1b", response.Registrant.Address[0]);
            Assert.AreEqual("Lastra a Signa", response.Registrant.Address[1]);
            Assert.AreEqual("50100", response.Registrant.Address[2]);
            Assert.AreEqual("FI", response.Registrant.Address[3]);
            Assert.AreEqual("IT", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("GIF-0000004711R", response.AdminContact.RegistryId);
            Assert.AreEqual("FRANCESCO CACCHIANI2", response.AdminContact.Name);
            Assert.AreEqual("FRANCESCO CACCHIANI", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2011, 04, 04, 16, 58, 43, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Via Ilio Barontini 1b", response.AdminContact.Address[0]);
            Assert.AreEqual("Lastra a Signa", response.AdminContact.Address[1]);
            Assert.AreEqual("50100", response.AdminContact.Address[2]);
            Assert.AreEqual("FI", response.AdminContact.Address[3]);
            Assert.AreEqual("IT", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("GIF-0000004711R", response.TechnicalContact.RegistryId);
            Assert.AreEqual("FRANCESCO CACCHIANI2", response.TechnicalContact.Name);
            Assert.AreEqual("FRANCESCO CACCHIANI", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2010, 02, 26, 15, 47, 30, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2011, 04, 04, 16, 58, 43, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via Ilio Barontini 1b", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Lastra a Signa", response.TechnicalContact.Address[1]);
            Assert.AreEqual("50100", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FI", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.asidev.net", response.NameServers[0]);
            Assert.AreEqual("ns2.asidev.net", response.NameServers[1]);
            Assert.AreEqual("ns3.asipec.com", response.NameServers[2]);
            Assert.AreEqual("ns4.asipec.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingUpdate", response.DomainStatus[0]);

            Assert.AreEqual(41, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_redemption_no_provider()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_redemption_no_provider.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Redemption, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("pilotielicottero.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("SEEWEB-MNT", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 03, 19, 00, 01, 06, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 01, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 03, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("PA424-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Pozzo Arturo", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("PA424-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Pozzo Arturo", response.AdminContact.Name);


             // TechnicalContact Details
            Assert.AreEqual("AB141417", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Antonio Baldassarra", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2007, 03, 01, 10, 25, 57, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2010, 07, 15, 09, 28, 14, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("C.so Lazio 9/a", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Frosinone", response.TechnicalContact.Address[1]);
            Assert.AreEqual("03100", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("dns.seeweb.it", response.NameServers[0]);
            Assert.AreEqual("dns2.seeweb.it", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("REDEMPTION-NO-PROVIDER", response.DomainStatus[0]);

            Assert.AreEqual(22, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "reserved.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("comunediroccaromana.it", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("RESERVED", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_unassignable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_unassignable.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("la.it", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("UNASSIGNABLE", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found_technical_contact()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_technical_contact.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("google.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Register.it s.p.a.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 12, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2009, 11, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOG175-ITNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Google Ireland Holdings", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("30 Herbert Street", response.Registrant.Address[0]);
            Assert.AreEqual("Dublin", response.Registrant.Address[1]);
            Assert.AreEqual("2", response.Registrant.Address[2]);
            Assert.AreEqual("IE", response.Registrant.Address[3]);
            Assert.AreEqual("IE", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("TT4277-ITNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Tsao Tu", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2008, 11, 27, 16, 47, 22, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("30 Herbert Street", response.AdminContact.Address[0]);
            Assert.AreEqual("Dublin", response.AdminContact.Address[1]);
            Assert.AreEqual("2", response.AdminContact.Address[2]);
            Assert.AreEqual("IE", response.AdminContact.Address[3]);
            Assert.AreEqual("IE", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("TS7016-ITNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Technical Services", response.TechnicalContact.Name);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns4.google.com", response.NameServers[1]);
            Assert.AreEqual("ns2.google.com", response.NameServers[2]);
            Assert.AreEqual("ns3.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(31, response.FieldsParsed);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "unavailable.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Unavailable", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("u34jedzcq.it", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("AVAILABLE", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("google.it", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor International Limited", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 12, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 04, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DUP430692088", response.Registrant.RegistryId);
            Assert.AreEqual("Google Ireland Holdings", response.Registrant.Name);
            Assert.AreEqual("Google Ireland Holdings", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.Registrant.Created);
            Assert.AreEqual(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.Registrant.Updated);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("70 Sir John Rogersons Quay", response.Registrant.Address[0]);
            Assert.AreEqual("Dublin", response.Registrant.Address[1]);
            Assert.AreEqual("2", response.Registrant.Address[2]);
            Assert.AreEqual("IE", response.Registrant.Address[3]);
            Assert.AreEqual("IE", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("DUP142437129", response.AdminContact.RegistryId);
            Assert.AreEqual("Tsao Tu", response.AdminContact.Name);
            Assert.AreEqual("Tu Tsao", response.AdminContact.Organization);
            Assert.AreEqual(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.AdminContact.Created);
            Assert.AreEqual(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.AdminContact.Updated);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("70 Sir John Rogersons Quay", response.AdminContact.Address[0]);
            Assert.AreEqual("Dublin", response.AdminContact.Address[1]);
            Assert.AreEqual("2", response.AdminContact.Address[2]);
            Assert.AreEqual("IE", response.AdminContact.Address[3]);
            Assert.AreEqual("IE", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("DUP430692088", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Ireland Holdings", response.TechnicalContact.Name);
            Assert.AreEqual("Google Ireland Holdings", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.TechnicalContact.Created);
            Assert.AreEqual(new DateTime(2013, 04, 21, 01, 05, 35, 000, DateTimeKind.Utc), response.TechnicalContact.Updated);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("70 Sir John Rogersons Quay", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Dublin", response.TechnicalContact.Address[1]);
            Assert.AreEqual("2", response.TechnicalContact.Address[2]);
            Assert.AreEqual("IE", response.TechnicalContact.Address[3]);
            Assert.AreEqual("IE", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns4.google.com", response.NameServers[1]);
            Assert.AreEqual("ns2.google.com", response.NameServers[2]);
            Assert.AreEqual("ns3.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(41, response.FieldsParsed);
        }

        [Test]
        public void Test_unavailable_status_unavailable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "unavailable_status_unavailable.txt");
            var response = parser.Parse("whois.nic.it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.it/it/Found", response.TemplateName);

            Assert.AreEqual("la.it", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("UNASSIGNABLE", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }
    }
}
