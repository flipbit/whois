using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Durban.Whois.Registry.Net.Za.Durban
{
    [TestFixture]
    public class DurbanParsingTests : ParsingTests
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
            var sample = SampleReader.Read("durban-whois.registry.net.za", "durban", "not_found.txt");
            var response = parser.Parse("durban-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(2, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("nosuchdomain.durban", response.DomainName.ToString());
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("durban-whois.registry.net.za", "durban", "found.txt");
            var response = parser.Parse("durban-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("durban-whois.registry.net.za/durban/Found", response.TemplateName);

            Assert.AreEqual("wordpress.durban", response.DomainName.ToString());
            Assert.AreEqual("dom_7G-9999", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("durban-whois1.registry.net.za", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2014, 11, 11, 6, 0, 3), response.Updated);
            Assert.AreEqual(new DateTime(2014, 11, 4, 6, 0, 1), response.Registered);
            Assert.AreEqual(new DateTime(2016, 11, 4, 6, 0, 1), response.Expiration);

             // Registrant Details
            Assert.AreEqual("mmr-132163", response.Registrant.RegistryId);
            Assert.AreEqual("DNStination Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("425 Market St 5th Floor", response.Registrant.Address[0]);
            Assert.AreEqual("San Francisco", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94105", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);

            Assert.AreEqual("+1.4155319335", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.4155319336", response.Registrant.FaxNumber);
            Assert.AreEqual("admin@dnstinations.com", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("mmr-132163", response.AdminContact.RegistryId);
            Assert.AreEqual("DNStination Inc.", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("425 Market St 5th Floor", response.AdminContact.Address[0]);
            Assert.AreEqual("San Francisco", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94105", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);

            Assert.AreEqual("+1.4155319335", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.4155319336", response.AdminContact.FaxNumber);
            Assert.AreEqual("admin@dnstinations.com", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("mmr-132163", response.BillingContact.RegistryId);
            Assert.AreEqual("DNStination Inc.", response.BillingContact.Name);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("425 Market St 5th Floor", response.BillingContact.Address[0]);
            Assert.AreEqual("San Francisco", response.BillingContact.Address[1]);
            Assert.AreEqual("CA", response.BillingContact.Address[2]);
            Assert.AreEqual("94105", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);

            Assert.AreEqual("+1.4155319335", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.4155319336", response.BillingContact.FaxNumber);
            Assert.AreEqual("admin@dnstinations.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("mmr-132163", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNStination Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("425 Market St 5th Floor", response.TechnicalContact.Address[0]);
            Assert.AreEqual("San Francisco", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94105", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+1.4155319335", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.4155319336", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("admin@dnstinations.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns3.markmonitor.com", response.NameServers[0]);
            Assert.AreEqual("ns1.markmonitor.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);

            Assert.AreEqual(51, response.FieldsParsed);
        }
    }
}
