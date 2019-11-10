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
            Assert.AreEqual("REGISTRATOR-REG-RIPN", response.Registrar.Name);

            Assert.AreEqual(new DateTime(1999, 12, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("ZAO MASTERHOST", response.Registrant.Organization);
            Assert.AreEqual("+7 495 7729720", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+7 495 7729723", response.Registrant.FaxNumber);
            Assert.AreEqual("domain-tld@masterhost.ru", response.Registrant.Email);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns.masterhost.ru", response.NameServers[0]);
            Assert.AreEqual("ns1.masterhost.ru", response.NameServers[1]);
            Assert.AreEqual("ns2.masterhost.ru", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED, DELEGATED, UNVERIFIED", response.DomainStatus[0]);

            Assert.AreEqual(13, response.FieldsParsed);
        }

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
            Assert.AreEqual("RU-CENTER-REG-RIPN", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2004, 03, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 03, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com.", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com.", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com.", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com.", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED, DELEGATED, VERIFIED", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
