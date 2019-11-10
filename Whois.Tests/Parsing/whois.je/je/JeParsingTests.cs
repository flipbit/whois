using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Je.Je
{
    [TestFixture]
    public class JeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.je", "je", "not_found.txt");
            var response = parser.Parse("whois.je", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.je/je/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.je", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Not Registered", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.je", "je", "found.txt");
            var response = parser.Parse("whois.je", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.je/je/Found", response.TemplateName);

            Assert.AreEqual("google.je", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2002, 10, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns4.google.com", response.NameServers[2]);
            Assert.AreEqual("ns3.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(12, response.FieldsParsed);
        }
    }
}
