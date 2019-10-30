using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.XnFzc2c9e2c
{
    [TestFixture]
    public class XnFzc2c9e2cParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.lk", "xn--fzc2c9e2c", "not_found.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.AreEqual(WhoisStatus.Unknown, response.Status);
            Assert.AreEqual(0, response.ContentLength);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.lk", "xn--fzc2c9e2c", "found.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lk/Found02", response.TemplateName);

            Assert.AreEqual("xn--fzc3a2azd8dsa2ktat.xn--fzc2c9e2c", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns3.pipedns.com.", response.NameServers[0]);

            Assert.AreEqual(5, response.FieldsParsed);
        }
    }
}
