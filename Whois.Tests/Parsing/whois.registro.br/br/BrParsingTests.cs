using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registro.Br.Br
{
    [TestFixture]
    public class BrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.registro.br", "br", "found.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "not_found.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_not_found_status_available_limited()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "not_found_status_available_limited.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found_status_registered.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_status_registered_limited()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found_status_registered_limited.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
