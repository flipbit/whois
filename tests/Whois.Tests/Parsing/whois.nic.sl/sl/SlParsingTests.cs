using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sl.Sl
{
    [TestFixture]
    public class SlParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.sl", "sl", "not_found.txt");
            var response = parser.Parse("whois.nic.sl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.sl/sl/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.sl", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.sl", "sl", "found.txt");
            var response = parser.Parse("whois.nic.sl", sample);

            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.sl/sl/Found", response.TemplateName);

            Assert.AreEqual("google.sl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NIC.SL (http://www.nic.sl)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2008, 05, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 05, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("C15964-1211155136", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("1-6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("1-6506188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("Ca", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("Us", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("C15964-1211155137", response.AdminContact.RegistryId);
            Assert.AreEqual("Ccops Domains", response.AdminContact.Name);
            Assert.AreEqual("Markmonitor Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.2083895740", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.AdminContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("10400 Overland Road Pmb 155", response.AdminContact.Address[0]);
            Assert.AreEqual("Boise", response.AdminContact.Address[1]);
            Assert.AreEqual("Id", response.AdminContact.Address[2]);
            Assert.AreEqual("83709", response.AdminContact.Address[3]);
            Assert.AreEqual("Us", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("C15964-1211155138", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ca", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Us", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(42, response.FieldsParsed);
        }
    }
}
