using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Jprs.Jp.CoJp
{
    [TestFixture]
    public class CoJpParsingTests : ParsingTests
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "pending_delete.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
