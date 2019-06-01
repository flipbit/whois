using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Srs.Net.Nz.Nz
{
    [TestFixture]
    public class NzParsingTests : ParsingTests
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void Test_other_status_pendingrelease()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "other_status_pendingrelease.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "throttled.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "invalid.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
