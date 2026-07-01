using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.UyCom
{
    [TestFixture]
    public class UyComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "uy.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("bingo.uy.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO705337", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Domain Exploitation International", response.Registrar.Name);


             // Registrant Details
            Assert.AreEqual("H122681", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("H122681", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("H122681", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("H122681", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.domain-exploitation.us.com", response.NameServers[0]);
            Assert.AreEqual("ns1.domain-exploitation.us.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(12, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "uy.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "uy.com", "found_status_registered.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("bestb.uy.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO493832", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Webfusion", response.Registrar.Name);
            Assert.AreEqual("1515", response.Registrar.IanaId);
            Assert.AreEqual("http://www.123-reg.co.uk/domain-names/", response.Registrar.Url);
            Assert.AreEqual("0845 859 0018", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 7, 10, 0, 27, 20, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 7, 12, 13, 49, 25, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 7, 12, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("MNT32524959440", response.Registrant.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.Registrant.Name);
            Assert.AreEqual("Identity Protect Limited", response.Registrant.Organization);
            Assert.AreEqual("+44.1483307527", response.Registrant.TelephoneNumber);
            Assert.AreEqual("bestb.uy.com@identity-protect.org", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("PO Box 795", response.Registrant.Address[0]);
            Assert.AreEqual("Godalming", response.Registrant.Address[1]);
            Assert.AreEqual("Surrey", response.Registrant.Address[2]);
            Assert.AreEqual("GU7 9GA", response.Registrant.Address[3]);
            Assert.AreEqual("GB", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("MNT32524959440", response.AdminContact.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.AdminContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.AdminContact.Organization);
            Assert.AreEqual("+44.1483307527", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("bestb.uy.com@identity-protect.org", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.AdminContact.Address[0]);
            Assert.AreEqual("Godalming", response.AdminContact.Address[1]);
            Assert.AreEqual("Surrey", response.AdminContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.AdminContact.Address[3]);
            Assert.AreEqual("GB", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("MNT32524959440", response.BillingContact.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.BillingContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.BillingContact.Organization);
            Assert.AreEqual("+44.1483307527", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+44.1483304031", response.BillingContact.FaxNumber);
            Assert.AreEqual("bestb.uy.com@identity-protect.org", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.BillingContact.Address[0]);
            Assert.AreEqual("Godalming", response.BillingContact.Address[1]);
            Assert.AreEqual("Surrey", response.BillingContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.BillingContact.Address[3]);
            Assert.AreEqual("GB", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("MNT32524959440", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.TechnicalContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.TechnicalContact.Organization);
            Assert.AreEqual("+44.1483307527", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("bestb.uy.com@identity-protect.org", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Godalming", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Surrey", response.TechnicalContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.TechnicalContact.Address[3]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.123-reg.co.uk", response.NameServers[0]);
            Assert.AreEqual("ns.123-reg.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(55, response.FieldsParsed);
        }
    }
}
