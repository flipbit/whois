using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Co.Ca.CoCa
{
    [TestFixture]
    public class CoCaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.co.ca", "co.ca", "not_found.txt");
            var response = parser.Parse("whois.co.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.ca/co.ca/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.co.ca", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.co.ca", "co.ca", "found.txt");
            var response = parser.Parse("whois.co.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.ca/co.ca/Found", response.TemplateName);

            Assert.AreEqual("internet.co.ca", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("RegCA Enterprises Inc. (www.reg.ca)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2005, 06, 25, 16, 03, 30, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 06, 25, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.canadawebhosting.com", response.NameServers[0]);
            Assert.AreEqual("ns2.canadawebhosting.com", response.NameServers[1]);

            Assert.AreEqual(7, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.co.ca", "co.ca", "reserved.txt");
            var response = parser.Parse("whois.co.ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.ca/co.ca/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }
    }
}
