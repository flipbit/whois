using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Sk.Nic.Sk.Sk
{
    [TestFixture]
    public class SkParsingTests : ParsingTests
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void Test_other_status_dom_dakt()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_dakt.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_dom_exp()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_exp.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_dom_held()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_held.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_dom_lnot()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_lnot.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_dom_ok()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_ok.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_dom_ta()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_ta.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_dom_warn()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_warn.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
