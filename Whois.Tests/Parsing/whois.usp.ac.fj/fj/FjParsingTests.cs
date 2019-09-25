using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Usp.Ac.Fj.Fj
{
    [TestFixture]
    public class FjParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.usp.ac.fj", "fj", "not_found.txt");
            var response = parser.Parse("whois.usp.ac.fj", "fj", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.usp.ac.fj/fj/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.fj", response.DomainName);

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.usp.ac.fj", "fj", "found.txt");
            var response = parser.Parse("whois.usp.ac.fj", "fj", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.usp.ac.fj/fj/Found", response.TemplateName);

            Assert.AreEqual("google.com.fj", response.DomainName);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(7, response.FieldsParsed);
        }
    }
}
