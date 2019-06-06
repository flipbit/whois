using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sgnic.Sg.Sg
{
    [TestFixture]
    public class SgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found.txt");
            var response = parser.Parse("whois.sgnic.sg", "sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_schema_1_with_ip()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found_nameservers_schema_1_with_ip.txt");
            var response = parser.Parse("whois.sgnic.sg", "sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_schema_2()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found_nameservers_schema_2.txt");
            var response = parser.Parse("whois.sgnic.sg", "sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "not_found.txt");
            var response = parser.Parse("whois.sgnic.sg", "sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.sgnic.sg", "sg", "found_status_registered.txt");
            var response = parser.Parse("whois.sgnic.sg", "sg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
