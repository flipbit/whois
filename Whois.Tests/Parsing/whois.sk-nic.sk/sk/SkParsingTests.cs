using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sk.Nic.Sk.Sk
{
    [TestFixture]
    public class SkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_dom_dakt()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_dakt.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("plac.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 04, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 05, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("TOMH-0091", response.AdminContact.RegistryId);
            Assert.AreEqual("Ing. Tomas Hanko", response.AdminContact.Name);
            Assert.AreEqual("0000000000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("TOMH0091@gmail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("L. Novomeskeho 2672/5, Trencin 91108", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("TOMH-0091", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Ing. Tomas Hanko", response.TechnicalContact.Name);
            Assert.AreEqual("0000000000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("TOMH0091@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("L. Novomeskeho 2672/5, Trencin 91108", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.dnparking.sk", response.NameServers[0]);
            Assert.AreEqual("ns2.dnparking.sk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_DAKT", response.DomainStatus[0]);

            Assert.AreEqual(17, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_dom_exp()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_exp.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Expired, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("kuphry.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("BCPE-0006", response.AdminContact.RegistryId);
            Assert.AreEqual("Bc. Peter Drienovsky", response.AdminContact.Name);
            Assert.AreEqual("+421 905 2398 07", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("peter@drienovsky.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("Hviezdoslavova 22, Zlate Moravce 95301", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("BCPE-0006", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Bc. Peter Drienovsky", response.TechnicalContact.Name);
            Assert.AreEqual("+421 905 2398 07", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("peter@drienovsky.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Hviezdoslavova 22, Zlate Moravce 95301", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.servage.net", response.NameServers[0]);
            Assert.AreEqual("ns2.servage.net", response.NameServers[1]);
            Assert.AreEqual("ns3.servage.net", response.NameServers[2]);
            Assert.AreEqual("ns4.servage.net", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_EXP", response.DomainStatus[0]);

            Assert.AreEqual(19, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_dom_held()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_held.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("plac.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 03, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 04, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("CROO-0002", response.AdminContact.RegistryId);
            Assert.AreEqual("crooce.com - the internet company, s.r.o.", response.AdminContact.Name);
            Assert.AreEqual("+421 2 2060 0000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("info@crooce.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("Panenska 24, Bratislava 811 03", response.AdminContact.Address[0]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_HELD", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_dom_lnot()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_lnot.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("dobramasaz.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("SECO-0007", response.AdminContact.RegistryId);
            Assert.AreEqual("SECORAMA", response.AdminContact.Name);
            Assert.AreEqual("0000000000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("hmalik@secorama.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("Kresankova 7/B, Bratislava 84105", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("FORP-0003", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Forplay, spol. s r.o.", response.TechnicalContact.Name);
            Assert.AreEqual("0905 403 404", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("info@forplay.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Laurinska 11, Bratislava - Stare mesto 811 01", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.brianlurie.com", response.NameServers[0]);
            Assert.AreEqual("ns2.brianlurie.com", response.NameServers[1]);
            Assert.AreEqual("ns3.brianlurie.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_LNOT", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_dom_ok()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_ok.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("google.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 06, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 07, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("MFAJ-0001", response.AdminContact.RegistryId);
            Assert.AreEqual("Maria Fajnorova, Patentova a znamkova kancelaria", response.AdminContact.Name);
            Assert.AreEqual("02-63811927", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("mfajnorova@fabap.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("Lietavska 9, Bratislava 851 06", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("MFAJ-0001", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Maria Fajnorova, Patentova a znamkova kancelaria", response.TechnicalContact.Name);
            Assert.AreEqual("02-63811927", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("mfajnorova@fabap.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Lietavska 9, Bratislava 851 06", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_OK", response.DomainStatus[0]);

            Assert.AreEqual(19, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_dom_ta()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_ta.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("plac.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("KATA-0423", response.AdminContact.RegistryId);
            Assert.AreEqual("Katarina Majercakova", response.AdminContact.Name);
            Assert.AreEqual("0907 555 883", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("majercakova.katarina@gmail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("Pradiaren 765/10, Kezmarok 060 01", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("KATA-0423", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Katarina Majercakova", response.TechnicalContact.Name);
            Assert.AreEqual("0907 555 883", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("majercakova.katarina@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Pradiaren 765/10, Kezmarok 060 01", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.dnparking.sk", response.NameServers[0]);
            Assert.AreEqual("ns2.dnparking.sk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_TA", response.DomainStatus[0]);

            Assert.AreEqual(17, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_dom_warn()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_warn.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("e-biznis.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 07, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 08, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("EVEC-0001", response.AdminContact.RegistryId);
            Assert.AreEqual("eVector s.r.o.", response.AdminContact.Name);
            Assert.AreEqual("421-37-6578941", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("info@evector.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("Coboriho 2, Nitra 94901", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("BEES-0002", response.TechnicalContact.RegistryId);
            Assert.AreEqual("BeeSoft s.r.o.", response.TechnicalContact.Name);
            Assert.AreEqual("421264530707", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Lamacska cesta 20, Bratislava 84103", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.beesoft.sk", response.NameServers[0]);
            Assert.AreEqual("ns2.beesoft.sk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_WARN", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "not_found.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sk-nic.sk/sk/Found", response.TemplateName);

            Assert.AreEqual("google.sk", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 06, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 07, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("MFAJ-0001", response.AdminContact.RegistryId);
            Assert.AreEqual("Maria Fajnorova, Patentova a znamkova kancelaria", response.AdminContact.Name);
            Assert.AreEqual("02-63811927", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("mfajnorova@fabap.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("Lietavska 9, Bratislava 851 06", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("MFAJ-0001", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Maria Fajnorova, Patentova a znamkova kancelaria", response.TechnicalContact.Name);
            Assert.AreEqual("02-63811927", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("mfajnorova@fabap.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Lietavska 9, Bratislava 851 06", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("DOM_OK", response.DomainStatus[0]);

            Assert.AreEqual(19, response.FieldsParsed);
        }
    }
}
