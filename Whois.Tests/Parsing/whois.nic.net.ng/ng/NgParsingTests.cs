using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Net.Ng.Ng
{
    [TestFixture]
    public class NgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.net.ng", "ng", "not_found.txt");
            var response = parser.Parse("whois.nic.net.ng", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ng", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.net.ng", "ng", "found.txt");
            var response = parser.Parse("whois.nic.net.ng", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("nic.net.ng", response.DomainName.ToString());
            Assert.AreEqual("6808-NIRA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("nira", response.Registrar.Name);
            Assert.AreEqual("nira", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2012, 08, 24, 13, 46, 14, 774, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 05, 13, 14, 27, 27, 009, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 07, 30, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("80023-NIRA", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Admin", response.Registrant.Name);
            Assert.AreEqual("Nigeria Internet Registration Association", response.Registrant.Organization);
            Assert.AreEqual("+2348086031704", response.Registrant.TelephoneNumber);
            Assert.AreEqual("admin@nira.org.ng", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("9 Kofo Abayomi Street", response.Registrant.Address[0]);
            Assert.AreEqual("Victoria Island", response.Registrant.Address[1]);
            Assert.AreEqual("Lagos", response.Registrant.Address[2]);
            Assert.AreEqual("101241", response.Registrant.Address[3]);
            Assert.AreEqual("NG", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("23141-NIRA", response.AdminContact.RegistryId);
            Assert.AreEqual("Nigeria Internet Registration Association (NIRA)", response.AdminContact.Organization);
            Assert.AreEqual("ugo@nira.org.ng", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("rns1.nic.net.ng", response.NameServers[0]);
            Assert.AreEqual("rns2.nic.net.ng", response.NameServers[1]);
            Assert.AreEqual("rns3.nic.net.ng", response.NameServers[2]);
            Assert.AreEqual("rns4.nic.net.ng", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.net.ng", "ng", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.net.ng", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ng", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.net.ng", "ng", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.net.ng", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("nic.net.ng", response.DomainName.ToString());
            Assert.AreEqual("6808-NIRA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("nira", response.Registrar.Name);
            Assert.AreEqual("whois.nic.ng", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2012, 08, 24, 13, 46, 14, 774, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 05, 13, 14, 27, 27, 009, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 07, 30, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("80023-NIRA", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Admin", response.Registrant.Name);
            Assert.AreEqual("Nigeria Internet Registration Association", response.Registrant.Organization);
            Assert.AreEqual("+2348086031704", response.Registrant.TelephoneNumber);
            Assert.AreEqual("admin@nira.org.ng", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("9 Kofo Abayomi Street", response.Registrant.Address[0]);
            Assert.AreEqual("Victoria Island", response.Registrant.Address[1]);
            Assert.AreEqual("Lagos", response.Registrant.Address[2]);
            Assert.AreEqual("101241", response.Registrant.Address[3]);
            Assert.AreEqual("NG", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("23141-NIRA", response.AdminContact.RegistryId);
            Assert.AreEqual("Nigeria Internet Registration Association (NIRA)", response.AdminContact.Organization);
            Assert.AreEqual("ugo@nira.org.ng", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("rns1.nic.net.ng", response.NameServers[0]);
            Assert.AreEqual("rns2.nic.net.ng", response.NameServers[1]);
            Assert.AreEqual("rns3.nic.net.ng", response.NameServers[2]);
            Assert.AreEqual("rns4.nic.net.ng", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(27, response.FieldsParsed);
        }
    }
}
