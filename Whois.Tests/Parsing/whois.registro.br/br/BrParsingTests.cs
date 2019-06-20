using System;
using NUnit.Framework;
using Whois.Models;
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
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/Found", response.TemplateName);

            Assert.AreEqual("hostgator.com.br", response.DomainName);

            // Registrar Details
            Assert.AreEqual("HOSTGATOR-BRASIL (43)", response.Registrar.Name);
            Assert.AreEqual("rob@hostgator.com.br", response.Registrar.AbuseEmail);

            Assert.AreEqual(new DateTime(2011, 5, 9, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(2005, 9, 12, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2018, 9, 12, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("008.852.780/0001-00", response.Registrant.RegistryId);
            Assert.AreEqual("Robledo Ribeiro Aloisio", response.Registrant.Name);
            Assert.AreEqual("Hostgator Brasil Hospedagem e suporte tecnico LTDA", response.Registrant.Organization);

             // AdminContact Details
            Assert.AreEqual("HOBRA", response.AdminContact.Name);

             // BillingContact Details
            Assert.AreEqual("HOBRA", response.BillingContact.Name);

             // TechnicalContact Details
            Assert.AreEqual("HOBRA", response.TechnicalContact.Name);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.hostgator.com.br", response.NameServers[0]);
            Assert.AreEqual("ns2.hostgator.com.br", response.NameServers[1]);
            Assert.AreEqual("ns3.hostgator.com.br", response.NameServers[2]);
            Assert.AreEqual("ns4.hostgator.com.br", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("published", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "not_found.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.br", response.DomainName);

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available_limited()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "not_found_status_available_limited.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/NotFoundThrottled", response.TemplateName);

            Assert.AreEqual("u34jedzcq.br", response.DomainName);

            Assert.AreEqual(2, response.FieldsParsed);        
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found_status_registered.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/Found", response.TemplateName);

            Assert.AreEqual("google.com.br", response.DomainName);

            // Registrar Details
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);

            Assert.AreEqual(new DateTime(2017, 4, 27, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(1999, 5, 18, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2018, 5, 18, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("06.990.590/0001-23", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);
            Assert.AreEqual("Google Brasil Internet Ltda", response.Registrant.Organization);

             // AdminContact Details
            Assert.AreEqual("DOADM17", response.AdminContact.Name);

             // BillingContact Details
            Assert.AreEqual("NAB51", response.BillingContact.Name);

             // TechnicalContact Details
            Assert.AreEqual("DOADM17", response.TechnicalContact.Name);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("published", response.DomainStatus[0]);

            Assert.AreEqual(17, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered_limited()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "found_status_registered_limited.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/FoundThrottled", response.TemplateName);

            Assert.AreEqual("registro.br", response.DomainName);

             // Registrant Details
            Assert.AreEqual("Núcleo de Informação e Coordenação do Ponto BR (662379)", response.Registrant.Organization);

            Assert.AreEqual(3, response.FieldsParsed);
        }
        
        [Test]
        public void Test_found_001hosting()
        {
            var sample = SampleReader.Read("whois.registro.br", "br", "001hosting.com.br.txt");
            var response = parser.Parse("whois.registro.br", "br", sample);

            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registro.br/br/Found", response.TemplateName);

            Assert.AreEqual("001hosting.com.br", response.DomainName);

            // Registrar Details
            Assert.AreEqual("registro@ultraprovedor.com.br", response.Registrar.AbuseEmail);

            Assert.AreEqual(new DateTime(2019, 4, 6, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(2001, 9, 19, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2020, 9, 19, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("350.562.738-05", response.Registrant.RegistryId);
            Assert.AreEqual("Ultra Provedor", response.Registrant.Organization);

             // AdminContact Details
            Assert.AreEqual("ULPRO5", response.AdminContact.Name);

             // BillingContact Details
            Assert.AreEqual("ULPRO5", response.BillingContact.Name);

             // TechnicalContact Details
            Assert.AreEqual("ULPRO5", response.TechnicalContact.Name);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.ultraprovedor.com.br", response.NameServers[0]);
            Assert.AreEqual("ns2.ultraprovedor.com.br", response.NameServers[1]);
            Assert.AreEqual("ns3.ultraprovedor.com.br", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("published", response.DomainStatus[0]);

            Assert.AreEqual(15, response.FieldsParsed);        
        }
    }
}
