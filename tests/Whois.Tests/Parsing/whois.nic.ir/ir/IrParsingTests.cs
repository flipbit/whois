using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ir.Ir
{
    [TestFixture]
    public class IrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ir", "ir", "not_found.txt");
            var response = parser.Parse("whois.nic.ir", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ir/ir/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ir", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ir", "ir", "found.txt");
            var response = parser.Parse("whois.nic.ir", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ir/ir/Found", response.TemplateName);

            Assert.AreEqual("google.ir", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2014, 02, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2014, 12, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("go438-irnic", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1 650 623 4000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1 650 618 8571", response.Registrant.FaxNumber);
            Assert.AreEqual("support@domainservicesltd.co.uk", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway, Mountain View, CA, US", response.Registrant.Address[0]);


             // AdminContact Details
            Assert.AreEqual("do210-irnic", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Services Ltd", response.AdminContact.Organization);
            Assert.AreEqual("+44 87 20229870", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+44 87 20229871", response.AdminContact.FaxNumber);
            Assert.AreEqual("admin@domainservicesltd.co.uk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("2nd Floor 145-147 St.John Street, London, London, UK", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("do210-irnic", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Services Ltd", response.TechnicalContact.Organization);
            Assert.AreEqual("+44 87 20229870", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+44 87 20229871", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("admin@domainservicesltd.co.uk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2nd Floor 145-147 St.John Street, London, London, UK", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns3.google.com", response.NameServers[0]);
            Assert.AreEqual("ns4.google.com", response.NameServers[1]);
            Assert.AreEqual("ns1.google.com", response.NameServers[2]);
            Assert.AreEqual("ns2.google.com", response.NameServers[3]);

            Assert.AreEqual(23, response.FieldsParsed);
        }
    }
}
