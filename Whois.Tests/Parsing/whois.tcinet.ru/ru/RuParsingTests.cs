using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tcinet.Ru.Ru
{
    [TestFixture]
    public class RuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.tcinet.ru", "ru", "found.txt");
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/Found", response.TemplateName);

            Assert.AreEqual("masterhost.ru", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("RD-RU", response.Registrar.Name);

            Assert.AreEqual(new DateTime(1999, 12, 15, 16, 20, 39, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2021, 12, 31, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual(@"LLC ""MASTERHOST""", response.Registrant.Organization);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns3.masterhost.ru", response.NameServers[0]);
            Assert.AreEqual("ns4.masterhost.ru", response.NameServers[1]);
            Assert.AreEqual("ns5.masterhost.ru", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED", response.DomainStatus[0]);
            Assert.AreEqual("DELEGATED", response.DomainStatus[1]);
            Assert.AreEqual("UNVERIFIED", response.DomainStatus[2]);

            Assert.AreEqual(10, response.FieldsParsed);        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tcinet.ru", "ru", "not_found.txt");
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.tcinet.ru", "ru", "found_status_registered.txt");
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/Found", response.TemplateName);

            Assert.AreEqual("google.ru", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("RU-CENTER-RU", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2004, 03, 03, 21, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2021, 03, 04, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google LLC", response.Registrant.Organization);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com.", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com.", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com.", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com.", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED", response.DomainStatus[0]);
            Assert.AreEqual("DELEGATED", response.DomainStatus[1]);
            Assert.AreEqual("VERIFIED", response.DomainStatus[2]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
