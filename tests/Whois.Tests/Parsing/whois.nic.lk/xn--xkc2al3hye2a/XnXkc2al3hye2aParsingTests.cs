using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.XnXkc2al3hye2a
{
    [TestFixture]
    public class XnXkc2al3hye2aParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.lk", "xn--xkc2al3hye2a", "not_found.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.AreEqual(WhoisStatus.Unknown, response.Status);
            Assert.AreEqual(0, response.ContentLength);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.lk", "xn--xkc2al3hye2a", "found.txt");
            var response = parser.Parse("whois.nic.lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lk/Found02", response.TemplateName);

            Assert.AreEqual("xn--4kcolx4fsa0gdt6j.xn--xkc2al3hye2a", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 04, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.pipedns.com.", response.NameServers[0]);
            Assert.AreEqual("ns2.pipedns.com.", response.NameServers[1]);
            Assert.AreEqual("ns3.pipedns.com.", response.NameServers[2]);

            Assert.AreEqual(7, response.FieldsParsed);
        }
    }
}
