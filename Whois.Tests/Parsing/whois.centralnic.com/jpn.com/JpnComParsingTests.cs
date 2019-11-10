using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.JpnCom
{
    [TestFixture]
    public class JpnComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "jpn.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "jpn.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("koi.jpn.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO492866", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Webfusion", response.Registrar.Name);
            Assert.AreEqual("http://www.123-reg.co.uk/domain-names/", response.Registrar.Url);
            Assert.AreEqual("0845 859 0018", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 7, 1, 0, 18, 14, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 6, 29, 13, 42, 35, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 6, 29, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("MNT78E22765897", response.Registrant.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.Registrant.Name);
            Assert.AreEqual("Identity Protect Limited", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("PO Box 795", response.Registrant.Address[0]);
            Assert.AreEqual("Godalming", response.Registrant.Address[1]);
            Assert.AreEqual("Surrey", response.Registrant.Address[2]);
            Assert.AreEqual("GU7 9GA", response.Registrant.Address[3]);
            Assert.AreEqual("GB", response.Registrant.Address[4]);

            Assert.AreEqual("+44.1483307527", response.Registrant.TelephoneNumber);
            Assert.AreEqual("koi.jpn.com@identity-protect.org", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("MNT78E22765897", response.AdminContact.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.AdminContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.AdminContact.Address[0]);
            Assert.AreEqual("Godalming", response.AdminContact.Address[1]);
            Assert.AreEqual("Surrey", response.AdminContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.AdminContact.Address[3]);
            Assert.AreEqual("GB", response.AdminContact.Address[4]);

            Assert.AreEqual("+44.1483307527", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("koi.jpn.com@identity-protect.org", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("MNT78E22765897", response.BillingContact.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.BillingContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.BillingContact.Address[0]);
            Assert.AreEqual("Godalming", response.BillingContact.Address[1]);
            Assert.AreEqual("Surrey", response.BillingContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.BillingContact.Address[3]);
            Assert.AreEqual("GB", response.BillingContact.Address[4]);

            Assert.AreEqual("+44.1483307527", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+44.1483304031", response.BillingContact.FaxNumber);
            Assert.AreEqual("koi.jpn.com@identity-protect.org", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("MNT78E22765897", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Identity Protection Service", response.TechnicalContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Godalming", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Surrey", response.TechnicalContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.TechnicalContact.Address[3]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+44.1483307527", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("koi.jpn.com@identity-protect.org", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.chaoshosting.co.uk", response.NameServers[0]);
            Assert.AreEqual("ns2.chaoshosting.co.uk", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(55, response.FieldsParsed);
        }
    }
}
