using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Nic.Tr.Tr
{
    [TestFixture]
    public class TrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_contact_person()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_contact_person.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_ip.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_nameservers_with_trailing_space()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_trailing_space.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_registrant_contact_outside_cityinoneline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_cityinoneline.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_registrant_contact_outside_citynextline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_citynextline.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_registrant_contact_turkey()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_turkey.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "error.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "invalid.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_status_registered.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
