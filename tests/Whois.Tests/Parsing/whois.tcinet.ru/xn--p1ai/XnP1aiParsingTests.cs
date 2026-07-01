using System;
using NUnit.Framework;
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
            var sample = SampleReader.Read("whois.tcinet.ru", "xn--p1ai", "found.txt");
            var response = parser.Parse("whois.tcinet.ru", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tcinet.ru/Found", response.TemplateName);

            Assert.AreEqual("xn----8sbc3ahklcs4adf.xn--p1ai", response.DomainName.ToString());
            Assert.AreEqual("форум-кубани.рф", response.DomainName.ToUnicodeString());

            // Registrar Details
            Assert.AreEqual("REGRU-RF", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2017, 12, 20, 17, 02, 51, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 12, 20, 17, 02, 51, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.reg.ru.", response.NameServers[0]);
            Assert.AreEqual("ns2.reg.ru.", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("REGISTERED", response.DomainStatus[0]);
            Assert.AreEqual("DELEGATED", response.DomainStatus[1]);
            Assert.AreEqual("UNVERIFIED", response.DomainStatus[2]);

            Assert.AreEqual(8, response.FieldsParsed);
        }
    }
}
