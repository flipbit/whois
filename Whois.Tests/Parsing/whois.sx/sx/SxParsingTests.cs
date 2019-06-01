using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Sx.Sx
{
    [TestFixture]
    public class SxParsingTests : ParsingTests
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void Test_other_status_premium_name()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "other_status_premium_name.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "unavailable.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
