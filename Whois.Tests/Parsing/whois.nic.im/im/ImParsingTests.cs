using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Nic.Im.Im
{
    [TestFixture]
    public class ImParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.im", "im", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.im", "im", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}