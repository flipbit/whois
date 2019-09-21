using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tcinet.Ru.XnP1ai
{
    [TestFixture]
    public class XnP1aiParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.tcinet.ru", "xn--p1ai", "not_found.txt");
            var response = parser.Parse("whois.tcinet.ru", "xn--p1ai", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tcinet.ru", "xn--p1ai", "found.txt");
            var response = parser.Parse("whois.tcinet.ru", "xn--p1ai", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/Found", response.TemplateName);

            Assert.AreEqual("xn----8sbc3ahklcs4adf.xn--p1ai", response.DomainName);

            // Registrar Details
            Assert.AreEqual("R01-REG-RF", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 11, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 11, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("+7 800 3020800", response.Registrant.TelephoneNumber);
            Assert.AreEqual("liderkubani@gmail.com", response.Registrant.Email);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.redsoft.ru.", response.NameServers[0]);
            Assert.AreEqual("ns2.redsoft.ru.", response.NameServers[1]);
            Assert.AreEqual("ns2.r01.ru.", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED, DELEGATED, VERIFIED", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
