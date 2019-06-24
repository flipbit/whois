using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sk.Nic.Sk.Sk
{
    [TestFixture]
    [Ignore("TODO")]
    public class SkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_dom_dakt()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_dakt.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_dom_exp()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_exp.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_dom_held()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_held.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_dom_lnot()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_lnot.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_dom_ok()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_ok.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_dom_ta()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_ta.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_dom_warn()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "other_status_dom_warn.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "not_found.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.sk-nic.sk", "sk", "found.txt");
            var response = parser.Parse("whois.sk-nic.sk", "sk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
