using System;
using NUnit.Framework;
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
            var response = parser.Parse("whois.tcinet.ru", sample);

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
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/Found", response.TemplateName);

            Assert.AreEqual("google.su", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("RUCENTER-SU", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2005, 10, 15, 20, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2021, 10, 15, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("domens@mail.com", response.Registrant.Email);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns3.nic.ru.", response.NameServers[0]);
            Assert.AreEqual("ns4.nic.ru.", response.NameServers[1]);
            Assert.AreEqual("ns8.nic.ru.", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED", response.DomainStatus[0]);
            Assert.AreEqual("DELEGATED", response.DomainStatus[1]);

            Assert.AreEqual(10, response.FieldsParsed);
        }
    }
}
