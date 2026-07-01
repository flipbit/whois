using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.ArCom
{
    [TestFixture]
    public class ArComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "ar.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "ar.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("hotel.ar.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO557730", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("CentralNic Ltd", response.Registrar.Name);
            Assert.AreEqual("+44.8700170900", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 4, 26, 0, 15, 40, DateTimeKind.Utc), response.Updated.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2008, 4, 25, 16, 22, 13, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 4, 25, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1323241", response.Registrant.RegistryId);
            Assert.AreEqual("Reserved Domains", response.Registrant.Name);
            Assert.AreEqual("CentralNic Ltd", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("35-39 Moorgate", response.Registrant.Address[0]);
            Assert.AreEqual("London", response.Registrant.Address[1]);
            Assert.AreEqual("EC2R 6AR", response.Registrant.Address[2]);
            Assert.AreEqual("GB", response.Registrant.Address[3]);

            Assert.AreEqual("+44.8700170900", response.Registrant.TelephoneNumber);
            Assert.AreEqual("domains@centralnic.com", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("H1323241", response.AdminContact.RegistryId);
            Assert.AreEqual("Reserved Domains", response.AdminContact.Name);
            Assert.AreEqual("CentralNic Ltd", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("35-39 Moorgate", response.AdminContact.Address[0]);
            Assert.AreEqual("London", response.AdminContact.Address[1]);
            Assert.AreEqual("EC2R 6AR", response.AdminContact.Address[2]);
            Assert.AreEqual("GB", response.AdminContact.Address[3]);

            Assert.AreEqual("+44.8700170900", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domains@centralnic.com", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("H1323241", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Reserved Domains", response.TechnicalContact.Name);
            Assert.AreEqual("CentralNic Ltd", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("35-39 Moorgate", response.TechnicalContact.Address[0]);
            Assert.AreEqual("London", response.TechnicalContact.Address[1]);
            Assert.AreEqual("EC2R 6AR", response.TechnicalContact.Address[2]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+44.8700170900", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("domains@centralnic.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns0.centralnic-dns.com", response.NameServers[0]);
            Assert.AreEqual("ns1.centralnic-dns.com", response.NameServers[1]);
            Assert.AreEqual("ns2.centralnic-dns.com", response.NameServers[2]);
            Assert.AreEqual("ns3.centralnic-dns.com", response.NameServers[3]);
            Assert.AreEqual("ns4.centralnic-dns.com", response.NameServers[4]);
            Assert.AreEqual("ns5.centralnic-dns.com", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(43, response.FieldsParsed);
        }
    }
}
