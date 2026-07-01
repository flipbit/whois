using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Bj.Bj
{
    [TestFixture]
    public class BjParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.bj", "bj", "not_found.txt");
            var response = parser.Parse("whois.nic.bj", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.bj/bj/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.bj", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.bj", "bj", "found.txt");
            var response = parser.Parse("whois.nic.bj", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.bj/bj/Found", response.TemplateName);

            Assert.AreEqual("google.bj", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 08, 10, 08, 57, 22, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 03, 25, 08, 57, 22, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("GOOGLE INC (ED0155)", response.Registrant.Name);
            Assert.AreEqual("+1.6506234000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.Registrant.FaxNumber);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("USA", response.Registrant.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway, Moutain View CA 94043, US", response.Registrant.Address[1]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);

            Assert.AreEqual(12, response.FieldsParsed);
        }
    }
}
