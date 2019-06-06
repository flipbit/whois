using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Org.Uy.Uy
{
    [TestFixture]
    public class UyParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.org.uy", "uy", "found.txt");
            var response = parser.Parse("whois.nic.org.uy", "uy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.nic.org.uy", "uy", "error.txt");
            var response = parser.Parse("whois.nic.org.uy", "uy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Error, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.org.uy", "uy", "not_found.txt");
            var response = parser.Parse("whois.nic.org.uy", "uy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.org.uy", "uy", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.org.uy", "uy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
