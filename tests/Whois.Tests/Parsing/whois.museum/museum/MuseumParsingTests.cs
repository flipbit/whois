using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Museum.Museum
{
    [TestFixture]
    public class MuseumParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.museum", "museum", "not_found.txt");
            var response = parser.Parse("whois.museum", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.museum/museum/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.museum", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.museum", "museum", "found.txt");
            var response = parser.Parse("whois.museum", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("musedoma.museum", response.DomainName.ToString());
            Assert.AreEqual("D778-MUSEUM", response.RegistryDomainId);


             // Registrant Details
            Assert.AreEqual("AC727-MUSEUM", response.Registrant.RegistryId);
            Assert.AreEqual("n/a", response.Registrant.Name);
            Assert.AreEqual("Museum Domain Management Association", response.Registrant.Organization);
            Assert.AreEqual("ck@nrm.se", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Frescativaegen 40", response.Registrant.Address[0]);
            Assert.AreEqual("Stockholm", response.Registrant.Address[1]);
            Assert.AreEqual("104 05", response.Registrant.Address[2]);
            Assert.AreEqual("SE", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("C728-MUSEUM", response.AdminContact.RegistryId);
            Assert.AreEqual("Cary Karp", response.AdminContact.Name);
            Assert.AreEqual("Museum Domain Management Association", response.AdminContact.Organization);
            Assert.AreEqual("ck@nic.museum", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Frescativaegen 40", response.AdminContact.Address[0]);
            Assert.AreEqual("Stockholm", response.AdminContact.Address[1]);
            Assert.AreEqual("104 05", response.AdminContact.Address[2]);
            Assert.AreEqual("SE", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("C728-MUSEUM", response.BillingContact.RegistryId);
            Assert.AreEqual("Cary Karp", response.BillingContact.Name);
            Assert.AreEqual("Museum Domain Management Association", response.BillingContact.Organization);
            Assert.AreEqual("ck@nic.museum", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Frescativaegen 40", response.BillingContact.Address[0]);
            Assert.AreEqual("Stockholm", response.BillingContact.Address[1]);
            Assert.AreEqual("104 05", response.BillingContact.Address[2]);
            Assert.AreEqual("SE", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("C728-MUSEUM", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Cary Karp", response.TechnicalContact.Name);
            Assert.AreEqual("Museum Domain Management Association", response.TechnicalContact.Organization);
            Assert.AreEqual("ck@nic.museum", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Frescativaegen 40", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Stockholm", response.TechnicalContact.Address[1]);
            Assert.AreEqual("104 05", response.TechnicalContact.Address[2]);
            Assert.AreEqual("SE", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("nic.frd.se", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(37, response.FieldsParsed);
        }
    }
}
