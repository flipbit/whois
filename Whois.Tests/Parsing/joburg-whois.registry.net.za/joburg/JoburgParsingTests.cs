using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Joburg.Whois.Registry.Net.Za.Joburg
{
    [TestFixture]
    public class JoburgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("joburg-whois.registry.net.za", "joburg", "not_found.txt");
            var response = parser.Parse("joburg-whois.registry.net.za", "joburg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("joburg-whois.registry.net.za", "joburg", "found.txt");
            var response = parser.Parse("joburg-whois.registry.net.za", "joburg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
