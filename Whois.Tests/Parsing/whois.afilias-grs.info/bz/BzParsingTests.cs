using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Bz
{
    [TestFixture]
    public class BzParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.afilias-grs.info", "bz", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "bz", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
        }
    }
}
