using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ua.Ua
{
    [TestFixture]
    public class UaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_clienthold()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_clienthold.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_clienttransferprohibited()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_clienttransferprohibited.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_graceperiod.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "pending_delete.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.PendingDelete, response.Status);
        }

        [Test]
        public void Test_other_status_redemptionperiod()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "other_status_redemptionperiod.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "not_found.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found_status_registered.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contacts_multiple()
        {
            var sample = SampleReader.Read("whois.ua", "ua", "found_contacts_multiple.txt");
            var response = parser.Parse("whois.ua", "ua", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
