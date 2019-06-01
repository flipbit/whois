using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Iana.Org.Tld
{
    [TestFixture]
    public class TldParsingTests : ParsingTests
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.iana.org", "tld", "not_assigned.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
