using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Joburg.Whois.Registry.Net.Za.Joburg
{
    [TestFixture]
    public class JoburgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("joburg-whois.registry.net.za", "joburg", "not_found.txt");
            var response = parser.Parse("joburg-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(2, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("nosuchdomain.joburg", response.DomainName.ToString());
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("joburg-whois.registry.net.za", "joburg", "found.txt");
            var response = parser.Parse("joburg-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(54, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("usedautos.joburg", response.DomainName.ToString());
            Assert.AreEqual("dom_7P-9999", response.RegistryDomainId);

            Assert.AreEqual("Lexsynergy", response.Registrar.Name);
            Assert.AreEqual("joburg-whois2.registry.net.za", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2014, 11, 10, 7, 8, 28), response.Updated);
            Assert.AreEqual(new DateTime(2014, 11, 3, 22, 0, 8), response.Registered);
            Assert.AreEqual(new DateTime(2015, 11, 3, 22, 0, 8), response.Expiration);
            Assert.AreEqual("LEX-5FP-22YL", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);
            Assert.AreEqual("The Car Trader (Pty) Ltd", response.Registrant.Organization);

            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("154 Bram Fischer Drive Randburg", response.Registrant.Address[0]);
            Assert.AreEqual("Johannesburg", response.Registrant.Address[1]);
            Assert.AreEqual("2194", response.Registrant.Address[2]);
            Assert.AreEqual("ZA", response.Registrant.Address[3]);

            Assert.AreEqual("+27.116860900", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+27.117896449", response.Registrant.FaxNumber);
            Assert.AreEqual("domains@autotrader.co.za", response.Registrant.Email);

            Assert.AreEqual("LEX-5FP-22YL", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("The Car Trader (Pty) Ltd", response.AdminContact.Organization);

            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("154 Bram Fischer Drive Randburg", response.AdminContact.Address[0]);
            Assert.AreEqual("Johannesburg", response.AdminContact.Address[1]);
            Assert.AreEqual("2194", response.AdminContact.Address[2]);
            Assert.AreEqual("ZA", response.AdminContact.Address[3]);

            Assert.AreEqual("+27.116860900", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+27.117896449", response.AdminContact.FaxNumber);
            Assert.AreEqual("domains@autotrader.co.za", response.AdminContact.Email);

            Assert.AreEqual("LEX-1-PGD", response.BillingContact.RegistryId);
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

            Assert.AreEqual("LEX-5FP-22YL", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.TechnicalContact.Name);
            Assert.AreEqual("The Car Trader (Pty) Ltd", response.TechnicalContact.Organization);

            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("154 Bram Fischer Drive Randburg", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Johannesburg", response.TechnicalContact.Address[1]);
            Assert.AreEqual("2194", response.TechnicalContact.Address[2]);
            Assert.AreEqual("ZA", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+27.116860900", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+27.117896449", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("domains@autotrader.co.za", response.TechnicalContact.Email);


            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.lexsynergy.net", response.NameServers[0]);
            Assert.AreEqual("ns2.lexsynergy.us", response.NameServers[1]);
            Assert.AreEqual("ns3.lexsynergy.info", response.NameServers[2]);

            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);
        }
    }
}
