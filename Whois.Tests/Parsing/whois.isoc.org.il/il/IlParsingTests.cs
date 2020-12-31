using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Isoc.Org.Il.Il
{
    [TestFixture]
    public class IlParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "not_found.txt");
            var response = parser.Parse("whois.isoc.org.il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.isoc.org.il/il/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_transfer_allowed()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "other_status_transfer_allowed.txt");
            var response = parser.Parse("whois.isoc.org.il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.isoc.org.il/il/Found", response.TemplateName);

            Assert.AreEqual("spd.co.il", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Israel Internet Association ISOC-IL", response.Registrar.Name);
            Assert.AreEqual("www.isoc.org.il", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2005, 01, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 08, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 08, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("avi hirsh", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("beeri 17", response.Registrant.Address[0]);
            Assert.AreEqual("ganney tikva", response.Registrant.Address[1]);
            Assert.AreEqual("55900", response.Registrant.Address[2]);
            Assert.AreEqual("Israel", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("II-AH9666-IL", response.AdminContact.RegistryId);
            Assert.AreEqual("avi hirsh", response.AdminContact.Name);
            Assert.AreEqual("972-68-719751", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("admin@spd.co.il", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("sPD", response.AdminContact.Address[0]);
            Assert.AreEqual("beeri 23", response.AdminContact.Address[1]);
            Assert.AreEqual("ganney tikva", response.AdminContact.Address[2]);
            Assert.AreEqual("55900", response.AdminContact.Address[3]);
            Assert.AreEqual("Israel", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("II-AH9666-IL", response.TechnicalContact.RegistryId);
            Assert.AreEqual("avi hirsh", response.TechnicalContact.Name);
            Assert.AreEqual("972-68-719751", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("admin@spd.co.il", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("sPD", response.TechnicalContact.Address[0]);
            Assert.AreEqual("beeri 23", response.TechnicalContact.Address[1]);
            Assert.AreEqual("ganney tikva", response.TechnicalContact.Address[2]);
            Assert.AreEqual("55900", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Israel", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.AreEqual("II-AH9666-IL", response.ZoneContact.RegistryId);
            Assert.AreEqual("avi hirsh", response.ZoneContact.Name);
            Assert.AreEqual("972-68-719751", response.ZoneContact.TelephoneNumber);
            Assert.AreEqual("admin@spd.co.il", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.AreEqual(5, response.ZoneContact.Address.Count);
            Assert.AreEqual("sPD", response.ZoneContact.Address[0]);
            Assert.AreEqual("beeri 23", response.ZoneContact.Address[1]);
            Assert.AreEqual("ganney tikva", response.ZoneContact.Address[2]);
            Assert.AreEqual("55900", response.ZoneContact.Address[3]);
            Assert.AreEqual("Israel", response.ZoneContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns11.spd.co.il", response.NameServers[0]);
            Assert.AreEqual("ns12.spd.co.il", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Transfer Allowed", response.DomainStatus[0]);

            Assert.AreEqual(28, response.FieldsParsed);
        }

        [Test]
        public void Test_locked()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "locked.txt");
            var response = parser.Parse("whois.isoc.org.il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Locked, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.isoc.org.il/il/Found", response.TemplateName);

            Assert.AreEqual("isoc.org.il", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Israel Internet Association ISOC-IL", response.Registrar.Name);
            Assert.AreEqual("www.isoc.org.il", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2010, 10, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Israel Internet Association (ISOC-IL)", response.Registrant.Name);
            Assert.AreEqual("+972 3 9700900", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.Registrant.FaxNumber);
            Assert.AreEqual("info-domains@isoc.org.il", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("6 Bareket st., POB 7210", response.Registrant.Address[0]);
            Assert.AreEqual("Petach Tikva", response.Registrant.Address[1]);
            Assert.AreEqual("49517", response.Registrant.Address[2]);
            Assert.AreEqual("Israel", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("II-DS1453-IL", response.AdminContact.RegistryId);
            Assert.AreEqual("Doron Shikmoni", response.AdminContact.Name);
            Assert.AreEqual("+972 3 9700900", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.AdminContact.FaxNumber);
            Assert.AreEqual("doron@isoc.org.il", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Israel Internet Association (ISOC-IL)", response.AdminContact.Address[0]);
            Assert.AreEqual("6 Bareket st., POB 7210", response.AdminContact.Address[1]);
            Assert.AreEqual("Petach Tikva", response.AdminContact.Address[2]);
            Assert.AreEqual("49517", response.AdminContact.Address[3]);
            Assert.AreEqual("Israel", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("II-AB17965-IL", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Ariel Biener", response.TechnicalContact.Name);
            Assert.AreEqual("+972 3 9700900", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ariel@isoc.org.il", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Israel Internet Associaiton (ISOC-IL)", response.TechnicalContact.Address[0]);
            Assert.AreEqual("6 Bareket st., POB 7210", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Petach Tikva", response.TechnicalContact.Address[2]);
            Assert.AreEqual("49517", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Israel", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.AreEqual("II-DS1453-IL", response.ZoneContact.RegistryId);
            Assert.AreEqual("Doron Shikmoni", response.ZoneContact.Name);
            Assert.AreEqual("+972 3 9700900", response.ZoneContact.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.ZoneContact.FaxNumber);
            Assert.AreEqual("doron@isoc.org.il", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.AreEqual(5, response.ZoneContact.Address.Count);
            Assert.AreEqual("Israel Internet Association (ISOC-IL)", response.ZoneContact.Address[0]);
            Assert.AreEqual("6 Bareket st., POB 7210", response.ZoneContact.Address[1]);
            Assert.AreEqual("Petach Tikva", response.ZoneContact.Address[2]);
            Assert.AreEqual("49517", response.ZoneContact.Address[3]);
            Assert.AreEqual("Israel", response.ZoneContact.Address[4]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns.isoc.org.il", response.NameServers[0]);
            Assert.AreEqual("grappa.isoc.org.il", response.NameServers[1]);
            Assert.AreEqual("aristo.tau.ac.il", response.NameServers[2]);
            Assert.AreEqual("relay.huji.ac.il", response.NameServers[3]);
            Assert.AreEqual("drns.isoc.org.il", response.NameServers[4]);
            Assert.AreEqual("sps-pb.isc.org", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Transfer Locked", response.DomainStatus[0]);

            Assert.AreEqual(57, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "not_found_status_available.txt");
            var response = parser.Parse("whois.isoc.org.il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.isoc.org.il/il/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "found.txt");
            var response = parser.Parse("whois.isoc.org.il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Locked, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.isoc.org.il/il/Found", response.TemplateName);

            Assert.AreEqual("isoc.org.il", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Israel Internet Association ISOC-IL", response.Registrar.Name);
            Assert.AreEqual("www.isoc.org.il", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2014, 01, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1996, 01, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Israel Internet Association (ISOC-IL)", response.Registrant.Name);
            Assert.AreEqual("+972 3 9700900", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.Registrant.FaxNumber);
            Assert.AreEqual("info-domains@isoc.org.il", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("6 Bareket st., POB 7210", response.Registrant.Address[0]);
            Assert.AreEqual("Petach Tikva", response.Registrant.Address[1]);
            Assert.AreEqual("49517", response.Registrant.Address[2]);
            Assert.AreEqual("Israel", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("II-DB11403-IL", response.AdminContact.RegistryId);
            Assert.AreEqual("Dina Beer", response.AdminContact.Name);
            Assert.AreEqual("+972 3 9700900", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.AdminContact.FaxNumber);
            Assert.AreEqual("dina.b@isoc.org.il", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Israel Internet Association (ISOC-IL)", response.AdminContact.Address[0]);
            Assert.AreEqual("6 Bareket st., POB 7210", response.AdminContact.Address[1]);
            Assert.AreEqual("Petach Tikva", response.AdminContact.Address[2]);
            Assert.AreEqual("49517", response.AdminContact.Address[3]);
            Assert.AreEqual("Israel", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("II-DB11403-IL", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Dina Beer", response.TechnicalContact.Name);
            Assert.AreEqual("+972 3 9700900", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dina.b@isoc.org.il", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Israel Internet Association (ISOC-IL)", response.TechnicalContact.Address[0]);
            Assert.AreEqual("6 Bareket st., POB 7210", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Petach Tikva", response.TechnicalContact.Address[2]);
            Assert.AreEqual("49517", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Israel", response.TechnicalContact.Address[4]);


             // ZoneContact Details
            Assert.AreEqual("II-DB11403-IL", response.ZoneContact.RegistryId);
            Assert.AreEqual("Dina Beer", response.ZoneContact.Name);
            Assert.AreEqual("+972 3 9700900", response.ZoneContact.TelephoneNumber);
            Assert.AreEqual("+972 3 9700901", response.ZoneContact.FaxNumber);
            Assert.AreEqual("dina.b@isoc.org.il", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.AreEqual(5, response.ZoneContact.Address.Count);
            Assert.AreEqual("Israel Internet Association (ISOC-IL)", response.ZoneContact.Address[0]);
            Assert.AreEqual("6 Bareket st., POB 7210", response.ZoneContact.Address[1]);
            Assert.AreEqual("Petach Tikva", response.ZoneContact.Address[2]);
            Assert.AreEqual("49517", response.ZoneContact.Address[3]);
            Assert.AreEqual("Israel", response.ZoneContact.Address[4]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns.isoc.org.il", response.NameServers[0]);
            Assert.AreEqual("grappa.isoc.org.il", response.NameServers[1]);
            Assert.AreEqual("aristo.tau.ac.il", response.NameServers[2]);
            Assert.AreEqual("relay.huji.ac.il", response.NameServers[3]);
            Assert.AreEqual("drns.isoc.org.il", response.NameServers[4]);
            Assert.AreEqual("sns-pb.isc.org", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Transfer Locked", response.DomainStatus[0]);

            Assert.AreEqual(49, response.FieldsParsed);
        }
    }
}
