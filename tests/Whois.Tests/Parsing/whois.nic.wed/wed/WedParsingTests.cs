using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Wed.Wed
{
    [TestFixture]
    public class WedParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.wed", "wed", "not_found.txt");
            var response = parser.Parse("whois.nic.wed", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotAvailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found02", response.TemplateName);

            Assert.AreEqual("u34jedzcq.wed", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Prohibited String - Object Cannot Be Registered", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.wed", "wed", "found.txt");
            var response = parser.Parse("whois.nic.wed", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("nic.wed", response.DomainName.ToString());
            Assert.AreEqual("963171-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("WED gTLD Admin Reserved", response.Registrar.Name);
            Assert.AreEqual("whois.nic.wed", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2014, 01, 24, 05, 00, 34, 240, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2013, 12, 29, 22, 02, 21, 427, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 12, 29, 22, 02, 21, 621, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("963170-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("Garth Miller", response.Registrant.Name);
            Assert.AreEqual("CoCCA Registry Services (NZ) Ltd.", response.Registrant.Organization);
            Assert.AreEqual("+64.94466370", response.Registrant.TelephoneNumber);
            Assert.AreEqual("garth.miller@cocca.org.nz", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("11a Wynyard Street", response.Registrant.Address[0]);
            Assert.AreEqual("Auckland", response.Registrant.Address[1]);
            Assert.AreEqual("AKL", response.Registrant.Address[2]);
            Assert.AreEqual("0624", response.Registrant.Address[3]);
            Assert.AreEqual("NZ", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("963170-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("Garth Miller", response.AdminContact.Name);
            Assert.AreEqual("CoCCA Registry Services (NZ) Ltd.", response.AdminContact.Organization);
            Assert.AreEqual("+64.94466370", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("garth.miller@cocca.org.nz", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("11a Wynyard Street", response.AdminContact.Address[0]);
            Assert.AreEqual("Auckland", response.AdminContact.Address[1]);
            Assert.AreEqual("AKL", response.AdminContact.Address[2]);
            Assert.AreEqual("0624", response.AdminContact.Address[3]);
            Assert.AreEqual("NZ", response.AdminContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.enetworksgy.com", response.NameServers[0]);
            Assert.AreEqual("ns2.enetworksgy.com", response.NameServers[1]);
            Assert.AreEqual("ns3.enetworksgy.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(9, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[3]);
            Assert.AreEqual("serverRenewProhibited", response.DomainStatus[4]);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[5]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[6]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[7]);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[8]);

            Assert.AreEqual("signed", response.DnsSecStatus);
            Assert.AreEqual(41, response.FieldsParsed);
        }
    }
}
