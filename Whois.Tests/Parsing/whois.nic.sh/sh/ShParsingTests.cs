using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sh.Sh
{
    [TestFixture]
    public class ShParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.sh", "sh", "not_found.txt");
            var response = parser.Parse("whois.nic.sh", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            AssertWriter.Write(response);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.sh", "sh", "found.txt");
            var response = parser.Parse("whois.nic.sh", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.sh/sh/Found", response.TemplateName);

            Assert.AreEqual("google.sh", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2014, 06, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DNS Admin", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Google Inc.", response.Registrant.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[1]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[2]);
            Assert.AreEqual("CA", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Live", response.DomainStatus[0]);

            Assert.AreEqual(12, response.FieldsParsed);
        }
    }
}
