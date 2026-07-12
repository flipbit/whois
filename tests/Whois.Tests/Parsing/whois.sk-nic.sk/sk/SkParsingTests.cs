using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sk.Nic.Sk.Sk
{
    public class SkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SkParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_other_status_dom_dakt()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "other_status_dom_dakt.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("plac.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 04, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 05, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("TOMH-0091", response.AdminContact.RegistryId);
            Assert.Equal("Ing. Tomas Hanko", response.AdminContact.Name);
            Assert.Equal("0000000000", response.AdminContact.TelephoneNumber);
            Assert.Equal("TOMH0091@gmail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("L. Novomeskeho 2672/5, Trencin 91108", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("TOMH-0091", response.TechnicalContact.RegistryId);
            Assert.Equal("Ing. Tomas Hanko", response.TechnicalContact.Name);
            Assert.Equal("0000000000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("TOMH0091@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("L. Novomeskeho 2672/5, Trencin 91108", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.dnparking.sk", response.NameServers[0]);
            Assert.Equal("ns2.dnparking.sk", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_DAKT", response.DomainStatus[0]);

            Assert.Equal(17, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_dom_exp()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "other_status_dom_exp.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Expired, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("kuphry.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("BCPE-0006", response.AdminContact.RegistryId);
            Assert.Equal("Bc. Peter Drienovsky", response.AdminContact.Name);
            Assert.Equal("+421 905 2398 07", response.AdminContact.TelephoneNumber);
            Assert.Equal("peter@drienovsky.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("Hviezdoslavova 22, Zlate Moravce 95301", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("BCPE-0006", response.TechnicalContact.RegistryId);
            Assert.Equal("Bc. Peter Drienovsky", response.TechnicalContact.Name);
            Assert.Equal("+421 905 2398 07", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("peter@drienovsky.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("Hviezdoslavova 22, Zlate Moravce 95301", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.servage.net", response.NameServers[0]);
            Assert.Equal("ns2.servage.net", response.NameServers[1]);
            Assert.Equal("ns3.servage.net", response.NameServers[2]);
            Assert.Equal("ns4.servage.net", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_EXP", response.DomainStatus[0]);

            Assert.Equal(19, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_dom_held()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "other_status_dom_held.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("plac.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 03, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 04, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("CROO-0002", response.AdminContact.RegistryId);
            Assert.Equal("crooce.com - the internet company, s.r.o.", response.AdminContact.Name);
            Assert.Equal("+421 2 2060 0000", response.AdminContact.TelephoneNumber);
            Assert.Equal("info@crooce.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("Panenska 24, Bratislava 811 03", response.AdminContact.Address[0]);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_HELD", response.DomainStatus[0]);

            Assert.Equal(10, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_dom_lnot()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "dobramasaz.sk.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("dobramasaz.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("SECO-0007", response.AdminContact.RegistryId);
            Assert.Equal("SECORAMA", response.AdminContact.Name);
            Assert.Equal("0000000000", response.AdminContact.TelephoneNumber);
            Assert.Equal("hmalik@secorama.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("Kresankova 7/B, Bratislava 84105", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("FORP-0003", response.TechnicalContact.RegistryId);
            Assert.Equal("Forplay, spol. s r.o.", response.TechnicalContact.Name);
            Assert.Equal("0905 403 404", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("info@forplay.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("Laurinska 11, Bratislava - Stare mesto 811 01", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.brianlurie.com", response.NameServers[0]);
            Assert.Equal("ns2.brianlurie.com", response.NameServers[1]);
            Assert.Equal("ns3.brianlurie.com", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_LNOT", response.DomainStatus[0]);

            Assert.Equal(18, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_dom_ok()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "google.sk.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("google.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2010, 06, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 07, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("MFAJ-0001", response.AdminContact.RegistryId);
            Assert.Equal("Maria Fajnorova, Patentova a znamkova kancelaria", response.AdminContact.Name);
            Assert.Equal("02-63811927", response.AdminContact.TelephoneNumber);
            Assert.Equal("mfajnorova@fabap.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("Lietavska 9, Bratislava 851 06", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("MFAJ-0001", response.TechnicalContact.RegistryId);
            Assert.Equal("Maria Fajnorova, Patentova a znamkova kancelaria", response.TechnicalContact.Name);
            Assert.Equal("02-63811927", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("mfajnorova@fabap.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("Lietavska 9, Bratislava 851 06", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_OK", response.DomainStatus[0]);

            Assert.Equal(19, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_dom_ta()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "other_status_dom_ta.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("plac.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 08, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("KATA-0423", response.AdminContact.RegistryId);
            Assert.Equal("Katarina Majercakova", response.AdminContact.Name);
            Assert.Equal("0907 555 883", response.AdminContact.TelephoneNumber);
            Assert.Equal("majercakova.katarina@gmail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("Pradiaren 765/10, Kezmarok 060 01", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("KATA-0423", response.TechnicalContact.RegistryId);
            Assert.Equal("Katarina Majercakova", response.TechnicalContact.Name);
            Assert.Equal("0907 555 883", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("majercakova.katarina@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("Pradiaren 765/10, Kezmarok 060 01", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.dnparking.sk", response.NameServers[0]);
            Assert.Equal("ns2.dnparking.sk", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_TA", response.DomainStatus[0]);

            Assert.Equal(17, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_dom_warn()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "other_status_dom_warn.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("e-biznis.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 07, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 08, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("EVEC-0001", response.AdminContact.RegistryId);
            Assert.Equal("eVector s.r.o.", response.AdminContact.Name);
            Assert.Equal("421-37-6578941", response.AdminContact.TelephoneNumber);
            Assert.Equal("info@evector.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("Coboriho 2, Nitra 94901", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("BEES-0002", response.TechnicalContact.RegistryId);
            Assert.Equal("BeeSoft s.r.o.", response.TechnicalContact.Name);
            Assert.Equal("421264530707", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("Lamacska cesta 20, Bratislava 84103", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.beesoft.sk", response.NameServers[0]);
            Assert.Equal("ns2.beesoft.sk", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_WARN", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "not-found", "not_found.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found", "found.txt");
            var response = parser.Parse("whois.sk-nic.sk", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.sk-nic.sk/sk/found/01", response.TemplateName);

            Assert.Equal("google.sk", response.DomainName.ToString());

            Assert.Equal(new DateTime(2010, 06, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2011, 07, 23, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("MFAJ-0001", response.AdminContact.RegistryId);
            Assert.Equal("Maria Fajnorova, Patentova a znamkova kancelaria", response.AdminContact.Name);
            Assert.Equal("02-63811927", response.AdminContact.TelephoneNumber);
            Assert.Equal("mfajnorova@fabap.sk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("Lietavska 9, Bratislava 851 06", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("MFAJ-0001", response.TechnicalContact.RegistryId);
            Assert.Equal("Maria Fajnorova, Patentova a znamkova kancelaria", response.TechnicalContact.Name);
            Assert.Equal("02-63811927", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("mfajnorova@fabap.sk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("Lietavska 9, Bratislava 851 06", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("DOM_OK", response.DomainStatus[0]);

            Assert.Equal(19, response.FieldsParsed);
        }
    }
}
