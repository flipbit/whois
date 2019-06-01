using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Cdmon.Com.Com
{
    [TestFixture]
    public class ComParsingTests : ParsingTests
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cdmon.com", "com", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
