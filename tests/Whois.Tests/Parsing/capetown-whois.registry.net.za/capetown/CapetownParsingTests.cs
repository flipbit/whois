using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Capetown.Whois.Registry.Net.Za.Capetown
{
    [TestFixture]
    public class CapetownParsingTests : ParsingTests
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
            var sample = SampleReader.Read("capetown-whois.registry.net.za", "capetown", "not_found.txt");
            var response = parser.Parse("capetown-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
            Assert.AreEqual("nosuchdomain.capetown", response.DomainName.ToString());

            AssertWriter.Write(response);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");
            var response = parser.Parse("capetown-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);
           
            Assert.AreEqual("registry.capetown", response.DomainName.ToString());
            Assert.AreEqual("dom_3K3-9999", response.RegistryDomainId);

            Assert.AreEqual("capetown-whois2.registry.net.za", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2015, 5, 30, 9, 21, 0, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2015, 4, 1, 7, 41, 59, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 4, 1, 7, 41, 59, DateTimeKind.Utc), response.Expiration);
            Assert.AreEqual("LEX-7IC-235J", response.Registrant.RegistryId);
            Assert.AreEqual("Lucky Mokgabudi Masilela", response.Registrant.Name);
            Assert.AreEqual("ZA Central Registry", response.Registrant.Organization);

            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("COZA House, Gazelle Close Corporate Park South", response.Registrant.Address[0]);
            Assert.AreEqual("Midrand", response.Registrant.Address[1]);
            Assert.AreEqual("Gauteng", response.Registrant.Address[2]);
            Assert.AreEqual("1685", response.Registrant.Address[3]);
            Assert.AreEqual("ZA", response.Registrant.Address[4]);

            Assert.AreEqual("+27.113140077", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+27.113140088", response.Registrant.FaxNumber);
            Assert.AreEqual("legal@co.za", response.Registrant.Email);

            Assert.AreEqual("LEX-7IC-235J", response.AdminContact.RegistryId);
            Assert.AreEqual("Lucky Mokgabudi Masilela", response.AdminContact.Name);
            Assert.AreEqual("ZA Central Registry", response.AdminContact.Organization);

            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("COZA House, Gazelle Close Corporate Park South", response.AdminContact.Address[0]);
            Assert.AreEqual("Midrand", response.AdminContact.Address[1]);
            Assert.AreEqual("Gauteng", response.AdminContact.Address[2]);
            Assert.AreEqual("1685", response.AdminContact.Address[3]);
            Assert.AreEqual("ZA", response.AdminContact.Address[4]);

            Assert.AreEqual("+27.113140077", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+27.113140088", response.AdminContact.FaxNumber);
            Assert.AreEqual("legal@co.za", response.AdminContact.Email);

            Assert.AreEqual("LEX-1-1XMT", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Name Department", response.BillingContact.Name);
            Assert.AreEqual("Lexsynergy Limited", response.BillingContact.Organization);

            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("130 Hampstead House 176 Finchley Road", response.BillingContact.Address[0]);
            Assert.AreEqual("London", response.BillingContact.Address[1]);
            Assert.AreEqual("NW3 6BT", response.BillingContact.Address[2]);
            Assert.AreEqual("GB", response.BillingContact.Address[3]);

            Assert.AreEqual("+44.2081331319", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+44.2081331319", response.BillingContact.FaxNumber);
            Assert.AreEqual("domains@lexsynergy.com", response.BillingContact.Email);

            Assert.AreEqual("LEX-7IC-235J", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Lucky Mokgabudi Masilela", response.TechnicalContact.Name);
            Assert.AreEqual("ZA Central Registry", response.TechnicalContact.Organization);

            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("COZA House, Gazelle Close Corporate Park South", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Midrand", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Gauteng", response.TechnicalContact.Address[2]);
            Assert.AreEqual("1685", response.TechnicalContact.Address[3]);
            Assert.AreEqual("ZA", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+27.113140077", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+27.113140088", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("legal@co.za", response.TechnicalContact.Email);


            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.nic.capetown", response.NameServers[0]);
            Assert.AreEqual("ns1.dnservices.co.za", response.NameServers[1]);
        }
    }
}
