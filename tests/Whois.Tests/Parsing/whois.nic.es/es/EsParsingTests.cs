using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Es.Es
{
    [TestFixture]
    public class EsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.es", "es", "not_found.txt");
            var response = parser.Parse("whois.nic.es", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.es/es/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.es", "es", "found.txt");
            var response = parser.Parse("whois.nic.es", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.es/es/Found", response.TemplateName);

            Assert.AreEqual("google.es", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 10, 10, 07, 00, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 09, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOGLE INC.", response.Registrant.Name);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.google.com", response.NameServers[0]);
            Assert.AreEqual("ns1.google.com", response.NameServers[1]);

            Assert.AreEqual(8, response.FieldsParsed);
        }
    }
}
