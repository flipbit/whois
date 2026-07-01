using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sm.Sm
{
    [TestFixture]
    public class SmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.sm", "sm", "not_found.txt");
            var response = parser.Parse("whois.nic.sm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.sm/sm/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.sm", "sm", "found.txt");
            var response = parser.Parse("whois.nic.sm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.sm/sm/Found", response.TemplateName);

            Assert.AreEqual("google.sm", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2008, 08, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.AreEqual("Rose Hagan", response.Registrant.Name);
            Assert.AreEqual("Google, Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1 650 2530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1 650 6188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("US 94043 Mountain View (CA)", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("Domain Names Department", response.TechnicalContact.Name);
            Assert.AreEqual("Visiant Outsourcing S.r.l.", response.TechnicalContact.Organization);
            Assert.AreEqual("+39 011 3473520", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+39 011 3473522", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("domains.outsourcing@visiant.it", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Strada del Drosso 128/6", response.TechnicalContact.Address[0]);
            Assert.AreEqual("I 10135 Torino (TO)", response.TechnicalContact.Address[1]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(24, response.FieldsParsed);
        }
    }
}
