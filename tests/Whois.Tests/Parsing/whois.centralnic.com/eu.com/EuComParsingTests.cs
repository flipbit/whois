using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.EuCom
{
    [TestFixture]
    public class EuComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "eu.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "eu.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("walkabout.eu.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO85080", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("iTransact Ltd", response.Registrar.Name);
            Assert.AreEqual("01223 700322", response.Registrar.AbuseTelephoneNumber);
            Assert.AreEqual("www.itransact.ltd.uk", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 8, 15, 11, 25, 43, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 8, 14, 10, 14, 41, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 8, 14, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1045382", response.Registrant.RegistryId);
            Assert.AreEqual("Regent Inns Plc", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("77 Muswell Hill", response.Registrant.Address[0]);
            Assert.AreEqual("London", response.Registrant.Address[1]);
            Assert.AreEqual("N10 3PJ", response.Registrant.Address[2]);
            Assert.AreEqual("GB", response.Registrant.Address[3]);

            Assert.AreEqual("+44.2083753155", response.Registrant.TelephoneNumber);
            Assert.AreEqual("john.boyle@regent-inns.plc.uk", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("H64717", response.AdminContact.RegistryId);
            Assert.AreEqual("John Boyle", response.AdminContact.Name);
            Assert.AreEqual("Regent Inns Plc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("77 Muswell Hill", response.AdminContact.Address[0]);
            Assert.AreEqual("London", response.AdminContact.Address[1]);
            Assert.AreEqual("N10 3PJ", response.AdminContact.Address[2]);
            Assert.AreEqual("GB", response.AdminContact.Address[3]);

            Assert.AreEqual("+44.2083753155", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("john.boyle@regent-inns.plc.uk", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("H126914", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Constantine Pagonis", response.TechnicalContact.Name);
            Assert.AreEqual("iTransact Ltd", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("PO Box 430", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Cambridge", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CB1 2WE", response.TechnicalContact.Address[2]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+44.1223700322", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("constantine@itransact.ltd.uk", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns-1146.awsdns-15.org", response.NameServers[0]);
            Assert.AreEqual("ns-1741.awsdns-25.co.uk", response.NameServers[1]);
            Assert.AreEqual("ns-374.awsdns-46.com", response.NameServers[2]);
            Assert.AreEqual("ns-914.awsdns-50.net", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(41, response.FieldsParsed);
        }
    }
}
