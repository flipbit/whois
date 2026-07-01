using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tm.Tm
{
    [TestFixture]
    public class TmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.tm", "tm", "not_found.txt");
            var response = parser.Parse("whois.nic.tm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tm/tm/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.tm", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.tm", "tm", "found.txt");
            var response = parser.Parse("whois.nic.tm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tm/tm/Found", response.TemplateName);

            Assert.AreEqual("google.tm", response.DomainName.ToString());

             // Registrant Details
            Assert.AreEqual("DNS Admin", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Google Inc.", response.Registrant.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[1]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[2]);
            Assert.AreEqual("CA", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Client Updt Lock", response.DomainStatus[0]);

            Assert.AreEqual(9, response.FieldsParsed);
        }
    }
}
