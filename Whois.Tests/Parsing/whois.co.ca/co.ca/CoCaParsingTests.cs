using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Co.Ca.CoCa
{
    [TestFixture]
    public class CoCaParsingTests : ParsingTests
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.co.ca", "co.ca", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.co.ca", "co.ca", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.co.ca", "co.ca", "reserved.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
