using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Pr.Pr
{
    [TestFixture]
    public class PrParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.nic.pr", "pr", "error.txt");
            var response = parser.Parse("whois.nic.pr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Error, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.pr/pr/Error", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.pr", "pr", "not_found.txt");
            var response = parser.Parse("whois.nic.pr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.pr/pr/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.pr", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.pr", "pr", "found.txt");
            var response = parser.Parse("whois.nic.pr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.pr/pr/Found", response.TemplateName);

            Assert.AreEqual("google.pr", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2005, 09, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 09, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(8, response.FieldsParsed);
        }
    }
}
