using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.It.It
{
    [TestFixture]
    [Ignore("TODO")]
    public class ItParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_with_company_in_address()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_contact_with_company_in_address.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_with_organization()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_contact_with_organization.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_autorenewperiod_clientdeleteprohibited_clientupdateprohibited.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "not_found.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_other_status_client()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_client.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_graceperiod.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_inactive_noregistrar()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_inactive_noregistrar.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_no_provider()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_no_provider.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_ok.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_other_status_ok_autorenew()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_ok_autorenew.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_pendingdelete()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_pendingdelete_pendingdelete()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete_pendingdelete.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_pendingdelete_redemptionperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingdelete_redemptionperiod.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_pendingtransfer()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingtransfer.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_pendingtransfer_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingtransfer_autorenewperiod.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_pendingupdate()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingupdate.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_pendingupdate_autorenewperiod()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_pendingupdate_autorenewperiod.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_redemption_no_provider()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_redemption_no_provider.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "reserved.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }

        [Test]
        public void Test_other_status_unassignable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "other_status_unassignable.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_found_technical_contact()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_technical_contact.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "unavailable.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Unavailable, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_unavailable_status_unavailable()
        {
            var sample = SampleReader.Read("whois.nic.it", "it", "unavailable_status_unavailable.txt");
            var response = parser.Parse("whois.nic.it", "it", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Unavailable, response.Status);
        }
    }
}
