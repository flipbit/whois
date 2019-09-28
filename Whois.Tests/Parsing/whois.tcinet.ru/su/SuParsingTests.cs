using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tcinet.Ru.Su
{
    [TestFixture]
    public class SuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.tcinet.ru", "su", "not_found.txt");
            var response = parser.Parse("whois.tcinet.ru", "su", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tcinet.ru", "su", "found.txt");
            var response = parser.Parse("whois.tcinet.ru", "su", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/Found", response.TemplateName);

            Assert.AreEqual("google.su", response.DomainName);

            // Registrar Details
            Assert.AreEqual("RUCENTER-REG-FID", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2005, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 10, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("+7 495 9681807", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+7 495 9681807", response.Registrant.FaxNumber);
            Assert.AreEqual("cis@cis.su", response.Registrant.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1073.hostgator.com.", response.NameServers[0]);
            Assert.AreEqual("ns1074.hostgator.com.", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED, DELEGATED, UNVERIFIED", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
