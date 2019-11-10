using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Hr.Hr
{
    [TestFixture]
    public class HrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dns.hr", "hr", "not_found.txt");
            var response = parser.Parse("whois.dns.hr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.hr/hr/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dns.hr", "hr", "found.txt");
            var response = parser.Parse("whois.dns.hr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.hr/hr/Found", response.TemplateName);

            Assert.AreEqual("google.hr", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2014, 09, 21, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DD274636-DNSHR", response.Registrant.RegistryId);
            Assert.AreEqual("Džanan Drobić", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Sayber d.o.o.", response.Registrant.Address[0]);
            Assert.AreEqual("Poljanička 22", response.Registrant.Address[1]);
            Assert.AreEqual("10110 Zagreb", response.Registrant.Address[2]);
            Assert.AreEqual("Hrvatska", response.Registrant.Address[3]);

             // TechnicalContact Details
            Assert.AreEqual("DD274636-DNSHR", response.TechnicalContact.RegistryId);

            Assert.AreEqual(10, response.FieldsParsed);
        }
    }
}
