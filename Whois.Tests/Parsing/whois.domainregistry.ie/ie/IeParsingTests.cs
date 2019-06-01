using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Domainregistry.Ie.Ie
{
    [TestFixture]
    public class IeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_contacts_multiple()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_multiple.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_contacts_not_matching_id()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_contacts_not_matching_id.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_nameservers_with_ip.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found_status_registered.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
