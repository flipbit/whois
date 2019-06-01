using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Jprs.Jp.NeJp
{
    [TestFixture]
    public class NeJpParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found_status_registered.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_reserved_status_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved_status_reserved.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
