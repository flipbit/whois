using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domainregistry.Ie.Ie
{
    [TestFixture]
    public class IeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found.txt");
            var response = parser.Parse("whois.domainregistry.ie", "ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts_multiple()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_multiple.txt");
            var response = parser.Parse("whois.domainregistry.ie", "ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts_not_matching_id()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_not_matching_id.txt");
            var response = parser.Parse("whois.domainregistry.ie", "ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.domainregistry.ie", "ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "not_found.txt");
            var response = parser.Parse("whois.domainregistry.ie", "ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_status_registered.txt");
            var response = parser.Parse("whois.domainregistry.ie", "ie", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
