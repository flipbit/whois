using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.BrCom
{
    [TestFixture]
    public class BrComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "br.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "br.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("billboard.br.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO624205", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Network Solutions LLC", response.Registrar.Name);
            Assert.AreEqual("http://www.networksolutions.com/", response.Registrar.Url);
            Assert.AreEqual("+1.9046806600", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2012, 1, 16, 16, 23, 18, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 4, 17, 12, 22, 49, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 4, 17, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("36542943", response.Registrant.RegistryId);
            Assert.AreEqual("Antonio Camarotti Pinto", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Rua Urussui, 238", response.Registrant.Address[0]);
            Assert.AreEqual("#22", response.Registrant.Address[1]);
            Assert.AreEqual("Sao Paulo", response.Registrant.Address[2]);
            Assert.AreEqual("Sao Paulo", response.Registrant.Address[3]);
            Assert.AreEqual("04542-050", response.Registrant.Address[4]);
            Assert.AreEqual("BR", response.Registrant.Address[5]);

            Assert.AreEqual("+1.551130787711", response.Registrant.TelephoneNumber);
            Assert.AreEqual("ac@bpp.bz", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("36542943", response.AdminContact.RegistryId);
            Assert.AreEqual("Antonio Camarotti Pinto", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("Rua Urussui, 238", response.AdminContact.Address[0]);
            Assert.AreEqual("#22", response.AdminContact.Address[1]);
            Assert.AreEqual("Sao Paulo", response.AdminContact.Address[2]);
            Assert.AreEqual("Sao Paulo", response.AdminContact.Address[3]);
            Assert.AreEqual("04542-050", response.AdminContact.Address[4]);
            Assert.AreEqual("BR", response.AdminContact.Address[5]);

            Assert.AreEqual("+1.551130787711", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("ac@bpp.bz", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("36542943", response.BillingContact.RegistryId);
            Assert.AreEqual("Antonio Camarotti Pinto", response.BillingContact.Name);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Rua Urussui, 238", response.BillingContact.Address[0]);
            Assert.AreEqual("Sao Paulo", response.BillingContact.Address[1]);
            Assert.AreEqual("Sao Paulo", response.BillingContact.Address[2]);
            Assert.AreEqual("04542-050", response.BillingContact.Address[3]);
            Assert.AreEqual("BR", response.BillingContact.Address[4]);

            Assert.AreEqual("+1.551130787711", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("ac@bpp.bz", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("36542943", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Antonio Camarotti Pinto", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Rua Urussui, 238", response.TechnicalContact.Address[0]);
            Assert.AreEqual("#22", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Sao Paulo", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Sao Paulo", response.TechnicalContact.Address[3]);
            Assert.AreEqual("04542-050", response.TechnicalContact.Address[4]);
            Assert.AreEqual("BR", response.TechnicalContact.Address[5]);

            Assert.AreEqual("+1.551130787711", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("ac@bpp.bz", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.locaweb.com.br", response.NameServers[0]);
            Assert.AreEqual("ns2.locaweb.com.br", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("renewPeriod", response.DomainStatus[2]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(55, response.FieldsParsed);
        }
    }
}
