using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Bz
{
    public class BzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public BzParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "bz", "not-found", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "bz", "found", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
        }
    }
}
