using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Xxx.Xxx
{
    [TestFixture]
    public class XxxParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.xxx", "xxx", "not_found.txt");
            var response = parser.Parse("whois.nic.xxx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.xxx", "xxx", "found.txt");
            var response = parser.Parse("whois.nic.xxx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("masala.xxx", response.DomainName.ToString());
            Assert.AreEqual("D130773-XXX", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Mesh Digital Limited (R3228-XXX)", response.Registrar.Name);
            Assert.AreEqual("1390", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2013, 12, 02, 22, 20, 04, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 12, 01, 01, 37, 55, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 12, 01, 01, 37, 55, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("MNT5BB23000590", response.Registrant.RegistryId);
            Assert.AreEqual("Domainmonster.com Privacy Service", response.Registrant.Name);
            Assert.AreEqual("Identity Protect Limited", response.Registrant.Organization);
            Assert.AreEqual("+44.1483307527", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+44.1483304031", response.Registrant.FaxNumber);
            Assert.AreEqual("masala.xxx@privatemonster.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("PO Box 795", response.Registrant.Address[0]);
            Assert.AreEqual("Godalming", response.Registrant.Address[1]);
            Assert.AreEqual("Surrey", response.Registrant.Address[2]);
            Assert.AreEqual("GU7 9GA", response.Registrant.Address[3]);
            Assert.AreEqual("GB", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("MNT5BB23000590", response.AdminContact.RegistryId);
            Assert.AreEqual("Domainmonster.com Privacy Service", response.AdminContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.AdminContact.Organization);
            Assert.AreEqual("+44.1483307527", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+44.1483304031", response.AdminContact.FaxNumber);
            Assert.AreEqual("masala.xxx@privatemonster.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.AdminContact.Address[0]);
            Assert.AreEqual("Godalming", response.AdminContact.Address[1]);
            Assert.AreEqual("Surrey", response.AdminContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.AdminContact.Address[3]);
            Assert.AreEqual("GB", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("MNT5BB23000590", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domainmonster.com Privacy Service", response.TechnicalContact.Name);
            Assert.AreEqual("Identity Protect Limited", response.TechnicalContact.Organization);
            Assert.AreEqual("+44.1483307527", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+44.1483304031", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("masala.xxx@privatemonster.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("PO Box 795", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Godalming", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Surrey", response.TechnicalContact.Address[2]);
            Assert.AreEqual("GU7 9GA", response.TechnicalContact.Address[3]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns39.domaincontrol.com", response.NameServers[0]);
            Assert.AreEqual("ns40.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(44, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.xxx", "xxx", "reserved.txt");
            var response = parser.Parse("whois.nic.xxx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.xxx/xxx/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }
    }
}
