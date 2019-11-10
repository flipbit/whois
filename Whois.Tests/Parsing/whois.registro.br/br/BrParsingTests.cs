using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registro.Br.Br
{
    [TestFixture]
    public class BrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.registro.br", "br", "found.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/Found", response.TemplateName);

            Assert.AreEqual("hostgator.com.br", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("HOSTGATOR-BRASIL (43)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 05, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 09, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 09, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("008.852.780/0001-00", response.Registrant.RegistryId);
            Assert.AreEqual("Robledo Ribeiro Aloisio", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("HOBRA", response.AdminContact.RegistryId);
            Assert.AreEqual("Hostgator Brasil", response.AdminContact.Name);
            Assert.AreEqual("rob@hostgator.com.br", response.AdminContact.Email);
            Assert.AreEqual(new DateTime(2007, 12, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);


             // BillingContact Details
            Assert.AreEqual("HOBRA", response.BillingContact.RegistryId);
            Assert.AreEqual("Hostgator Brasil", response.BillingContact.Name);
            Assert.AreEqual("rob@hostgator.com.br", response.BillingContact.Email);
            Assert.AreEqual(new DateTime(2007, 12, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.BillingContact.Created);


             // TechnicalContact Details
            Assert.AreEqual("HOBRA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Hostgator Brasil", response.TechnicalContact.Name);
            Assert.AreEqual("rob@hostgator.com.br", response.TechnicalContact.Email);
            Assert.AreEqual(new DateTime(2007, 12, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.hostgator.com.br", response.NameServers[0]);
            Assert.AreEqual("ns2.hostgator.com.br", response.NameServers[1]);
            Assert.AreEqual("ns3.hostgator.com.br", response.NameServers[2]);
            Assert.AreEqual("ns4.hostgator.com.br", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("published", response.DomainStatus[0]);

            Assert.AreEqual(22, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "not_found.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.br", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available_limited()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "not_found_status_available_limited.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/NotFoundThrottled", response.TemplateName);

            Assert.AreEqual("u34jedzcq.br", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found_status_registered.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/Found", response.TemplateName);

            Assert.AreEqual("google.com.br", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2017, 04, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 05, 18, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("06.990.590/0001-23", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("DOADM17", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Admin", response.AdminContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);
            Assert.AreEqual(new DateTime(2010, 05, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);


             // BillingContact Details
            Assert.AreEqual("NAB51", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("DOADM17", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Admin", response.TechnicalContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);
            Assert.AreEqual(new DateTime(2010, 05, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("published", response.DomainStatus[0]);

            Assert.AreEqual(20, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered_limited()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found_status_registered_limited.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/FoundThrottled", response.TemplateName);

            Assert.AreEqual("registro.br", response.DomainName.ToString());

             // Registrant Details
            Assert.AreEqual("Núcleo de Informação e Coordenação do Ponto BR (662379)", response.Registrant.Name);

            Assert.AreEqual(3, response.FieldsParsed);
        }
        
        [Test]
        public void Test_found_001hosting()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "001hosting.com.br.txt");
            var response = parser.Parse("whois.registro.br", sample);

            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/Found", response.TemplateName);

            Assert.AreEqual("001hosting.com.br", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2019, 04, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 09, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("350.562.738-05", response.Registrant.RegistryId);
            Assert.AreEqual("Ultra Provedor", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("ULPRO5", response.AdminContact.RegistryId);
            Assert.AreEqual("Ultra Provedor", response.AdminContact.Name);
            Assert.AreEqual("registro@ultraprovedor.com.br", response.AdminContact.Email);
            Assert.AreEqual(new DateTime(2018, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);


             // BillingContact Details
            Assert.AreEqual("ULPRO5", response.BillingContact.RegistryId);
            Assert.AreEqual("Ultra Provedor", response.BillingContact.Name);
            Assert.AreEqual("registro@ultraprovedor.com.br", response.BillingContact.Email);
            Assert.AreEqual(new DateTime(2018, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.BillingContact.Created);


             // TechnicalContact Details
            Assert.AreEqual("ULPRO5", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Ultra Provedor", response.TechnicalContact.Name);
            Assert.AreEqual("registro@ultraprovedor.com.br", response.TechnicalContact.Email);
            Assert.AreEqual(new DateTime(2018, 02, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.ultraprovedor.com.br", response.NameServers[0]);
            Assert.AreEqual("ns2.ultraprovedor.com.br", response.NameServers[1]);
            Assert.AreEqual("ns3.ultraprovedor.com.br", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("published", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }
    }
}
