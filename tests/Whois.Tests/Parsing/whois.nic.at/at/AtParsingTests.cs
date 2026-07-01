using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.At.At
{
    [TestFixture]
    public class AtParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.at", "at", "not_found.txt");
            var response = parser.Parse("whois.nic.at", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.at/at/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.at", "at", "found.txt");
            var response = parser.Parse("whois.nic.at", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.at/at/Found", response.TemplateName);

            Assert.AreEqual("google.at", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 04, 26, 17, 57, 27, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.AreEqual("GI7803022-NICAT", response.Registrant.RegistryId);

             // AdminContact Details
            Assert.AreEqual("GI7803024-NICAT", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+16502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+16502530001", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("94043", response.AdminContact.Address[1]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[2]);
            Assert.AreEqual("United States", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("GI1919751-NICAT", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+16506234000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+16506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("USA-94043", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Mountain View, CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(49, response.FieldsParsed);
        }
    }
}
