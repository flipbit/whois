using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cctld.By.By
{
    [TestFixture]
    public class ByParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cctld.by", "by", "not_found.txt");
            var response = parser.Parse("whois.cctld.by", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cctld.by/by/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cctld.by", "by", "found.txt");
            var response = parser.Parse("whois.cctld.by", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cctld.by/by/Found", response.TemplateName);

            Assert.AreEqual("active.by", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Active Technologies LLC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 12, 16, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(2003, 2, 2, 0, 0, 0), response.Registered);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.activeby.net", response.NameServers[0]);
            Assert.AreEqual("ns2.activeby.net", response.NameServers[1]);

            Assert.AreEqual(7, response.FieldsParsed);
        }
    }
}
