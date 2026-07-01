using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.AeOrg
{
    [TestFixture]
    public class AeOrgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "ae.org", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "ae.org", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("kidzlink.ae.org", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO887354", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("101Domain, Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.101domain.com", response.Registrar.Url);
            Assert.AreEqual("+1.7604448674", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 6, 9, 0, 12, 37, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2012, 8, 3, 15, 37, 33, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 8, 3, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("RWG000000003DA24", response.Registrant.RegistryId);
            Assert.AreEqual("IPC C/O Clarenter", response.Registrant.Name);
            Assert.AreEqual("Clarenter", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("110 E Broward Blvd", response.Registrant.Address[0]);
            Assert.AreEqual("Ste. 1720", response.Registrant.Address[1]);
            Assert.AreEqual("Fort Lauderdale", response.Registrant.Address[2]);
            Assert.AreEqual("FL", response.Registrant.Address[3]);
            Assert.AreEqual("33301", response.Registrant.Address[4]);
            Assert.AreEqual("US", response.Registrant.Address[5]);

            Assert.AreEqual("+1.18888443911", response.Registrant.TelephoneNumber);
            Assert.AreEqual("patricia@internationalpreschoolcurriculum.com", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("RWG000000003DA24", response.AdminContact.RegistryId);
            Assert.AreEqual("IPC C/O Clarenter", response.AdminContact.Name);
            Assert.AreEqual("Clarenter", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("110 E Broward Blvd", response.AdminContact.Address[0]);
            Assert.AreEqual("Ste. 1720", response.AdminContact.Address[1]);
            Assert.AreEqual("Fort Lauderdale", response.AdminContact.Address[2]);
            Assert.AreEqual("FL", response.AdminContact.Address[3]);
            Assert.AreEqual("33301", response.AdminContact.Address[4]);
            Assert.AreEqual("US", response.AdminContact.Address[5]);

            Assert.AreEqual("+1.18888443911", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("patricia@internationalpreschoolcurriculum.com", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("RWG000000003DA25", response.BillingContact.RegistryId);
            Assert.AreEqual("Billing Department", response.BillingContact.Name);
            Assert.AreEqual("101Domain, Inc.", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("5858 Edison Pl.", response.BillingContact.Address[0]);
            Assert.AreEqual("Carlsbad", response.BillingContact.Address[1]);
            Assert.AreEqual("CA", response.BillingContact.Address[2]);
            Assert.AreEqual("92008", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);

            Assert.AreEqual("+1.7604448674", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.7605794996", response.BillingContact.FaxNumber);
            Assert.AreEqual("tech1@101domain.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("RWG000000003DA24", response.TechnicalContact.RegistryId);
            Assert.AreEqual("IPC C/O Clarenter", response.TechnicalContact.Name);
            Assert.AreEqual("Clarenter", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("110 E Broward Blvd", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Ste. 1720", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Fort Lauderdale", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FL", response.TechnicalContact.Address[3]);
            Assert.AreEqual("33301", response.TechnicalContact.Address[4]);
            Assert.AreEqual("US", response.TechnicalContact.Address[5]);

            Assert.AreEqual("+1.18888443911", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("patricia@internationalpreschoolcurriculum.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns37.domaincontrol.com", response.NameServers[0]);
            Assert.AreEqual("ns38.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(59, response.FieldsParsed);
        }
    }
}
