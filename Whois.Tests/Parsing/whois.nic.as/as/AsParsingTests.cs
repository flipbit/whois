using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.As.As
{
    [TestFixture]
    public class AsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.as", "as", "not_found.txt");
            var response = parser.Parse("whois.nic.as", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.as", "as", "found.txt");
            var response = parser.Parse("whois.nic.as", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.as/as/Found", response.TemplateName);

            Assert.AreEqual("google.as", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc. (http://www.markmonitor.com)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2000, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ST_CL_UPDATEPROHIBITED ST_CL_DELETEPROHIBITED ST_CL_TRANSFERPROHIBITED", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }
    }
}
