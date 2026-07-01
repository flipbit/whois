using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Design.Design
{
    [TestFixture]
    public class DesignParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.design", "design", "not_found.txt");
            var response = parser.Parse("whois.nic.design", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.design", "design", "found.txt");
            var response = parser.Parse("whois.nic.design", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("toplevel.design", response.DomainName.ToString());
            Assert.AreEqual("D7069819-CNIC", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Top Level Design, LLC", response.Registrar.Name);
            Assert.AreEqual("9999", response.Registrar.IanaId);
            Assert.AreEqual("whois.nic.wiki", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2015, 04, 21, 17, 48, 34, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2015, 02, 27, 16, 08, 32, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 02, 27, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H4596017", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);
            Assert.AreEqual("Top Level Design, LLC", response.Registrant.Organization);
            Assert.AreEqual("+1.5038888808", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6788841468", response.Registrant.FaxNumber);
            Assert.AreEqual("ray@tldesign.co", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("742 Ocean Club Place", response.Registrant.Address[0]);
            Assert.AreEqual("Fernandina Beach", response.Registrant.Address[1]);
            Assert.AreEqual("Florida", response.Registrant.Address[2]);
            Assert.AreEqual("32034", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("H4596017", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("Top Level Design, LLC", response.AdminContact.Organization);
            Assert.AreEqual("+1.5038888808", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6788841468", response.AdminContact.FaxNumber);
            Assert.AreEqual("ray@tldesign.co", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("742 Ocean Club Place", response.AdminContact.Address[0]);
            Assert.AreEqual("Fernandina Beach", response.AdminContact.Address[1]);
            Assert.AreEqual("Florida", response.AdminContact.Address[2]);
            Assert.AreEqual("32034", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("H4596017", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("Top Level Design, LLC", response.BillingContact.Organization);
            Assert.AreEqual("+1.5038888808", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.6788841468", response.BillingContact.FaxNumber);
            Assert.AreEqual("ray@tldesign.co", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("742 Ocean Club Place", response.BillingContact.Address[0]);
            Assert.AreEqual("Fernandina Beach", response.BillingContact.Address[1]);
            Assert.AreEqual("Florida", response.BillingContact.Address[2]);
            Assert.AreEqual("32034", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("H4596017", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.TechnicalContact.Name);
            Assert.AreEqual("Top Level Design, LLC", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.5038888808", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6788841468", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ray@tldesign.co", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("742 Ocean Club Place", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Fernandina Beach", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Florida", response.TechnicalContact.Address[2]);
            Assert.AreEqual("32034", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns-170.awsdns-21.com", response.NameServers[0]);
            Assert.AreEqual("ns-904.awsdns-49.net", response.NameServers[1]);
            Assert.AreEqual("ns-1067.awsdns-05.org", response.NameServers[2]);
            Assert.AreEqual("ns-1873.awsdns-42.co.uk", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(59, response.FieldsParsed);
        }
    }
}
