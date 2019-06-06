using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Durban.Whois.Registry.Net.Za.Durban
{
    [TestFixture]
    public class DurbanParsingTests : ParsingTests
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
            var sample = SampleReader.Read("durban-whois.registry.net.za", "durban", "not_found.txt");
            var response = parser.Parse("durban-whois.registry.net.za", "durban", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("durban-whois.registry.net.za", "durban", "found.txt");
            var response = parser.Parse("durban-whois.registry.net.za", "durban", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
