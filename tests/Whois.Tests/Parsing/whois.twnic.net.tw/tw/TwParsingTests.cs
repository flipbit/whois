using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Twnic.Net.Tw.Tw
{
    [TestFixture]
    public class TwParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.twnic.net.tw", "tw", "not_found.txt");
            var response = parser.Parse("whois.twnic.net.tw", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.twnic.net.tw/tw/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.twnic.net.tw", "tw", "found.txt");
            var response = parser.Parse("whois.twnic.net.tw", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.twnic.net.tw/tw/Found", response.TemplateName);

            Assert.AreEqual("google.com.tw", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Markmonitor, Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 11, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2000, 08, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(25, response.FieldsParsed);
        }
    }
}
