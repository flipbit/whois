using Whois.Visitors;
using NUnit.Framework;

namespace Whois.Parsing.Whois.Nic.It.It
{
    [TestFixture]
    public class ItParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.it", "it", "found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_contact_with_company_in_address()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_contact_with_company_in_address.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_contact_with_organization()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_contact_with_organization.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "not_found.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_client()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_client.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_graceperiod.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_inactive_noregistrar()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_inactive_noregistrar.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_no_provider()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_no_provider.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_ok.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_ok_autorenew()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_ok_autorenew.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_pendingdelete()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_pendingdelete_pendingdelete()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete_pendingdelete.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_pendingdelete_redemptionperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete_redemptionperiod.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_pendingtransfer()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingtransfer.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_pendingtransfer_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingtransfer_autorenewperiod.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_pendingupdate()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingupdate.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_pendingupdate_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingupdate_autorenewperiod.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_redemption_no_provider()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_redemption_no_provider.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "reserved.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_other_status_unassignable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_unassignable.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_technical_contact()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_technical_contact.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "unavailable.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "not_found_status_available.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_registered.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }

        [Test]
        public void Test_unavailable_status_unavailable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "unavailable_status_unavailable.txt");
            var match = visitor.Parse(sample);

            Assert.IsTrue(match.Success);
            Assert.IsTrue(sample.Length > 0);
        }
    }
}
