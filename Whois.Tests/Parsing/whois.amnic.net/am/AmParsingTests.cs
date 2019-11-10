using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Amnic.Net.Am
{
    [TestFixture]
    public class AmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.amnic.net", "am", "not_found.txt");
            var response = parser.Parse("whois.amnic.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.amnic.net", "am", "found.txt");
            var response = parser.Parse("whois.amnic.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(31, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.amnic.net/am/Found", response.TemplateName);

            Assert.AreEqual("google.am", response.DomainName.ToString());
            Assert.AreEqual("abcdomain", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 2, 13, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(1999, 6, 5, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2014, 4, 15, 0, 0, 0), response.Expiration);
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);

            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA,  94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


            Assert.AreEqual("Google, Inc.", response.AdminContact.Name);
            Assert.AreEqual("Google, Inc.", response.AdminContact.Organization);

            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View, CA, 94043", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);

            Assert.AreEqual("1 6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("1 6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google, Inc.", response.TechnicalContact.Organization);

            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View, CA, 94043", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);

            Assert.AreEqual("1 6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("1 6506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);


            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);
        }
    }
}
