using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cat.Cat
{
    [TestFixture]
    public class CatParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cat", "cat", "not_found.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("whois.cat/cat/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.cat", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cat/cat/Found", response.TemplateName);

            Assert.AreEqual("abril.cat", response.DomainName.ToString());
            Assert.AreEqual("REG-D42136", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2011, 1, 12, 16, 50, 9, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 4, 22, 09, 48, 30, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 4, 22, 09, 48, 30, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("edig-001455", response.Registrant.RegistryId);
            Assert.AreEqual("Amadeu Abril i Abril", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Carrer del carme 47", response.Registrant.Address[0]);
            Assert.AreEqual("Barcelona", response.Registrant.Address[1]);
            Assert.AreEqual("08001", response.Registrant.Address[2]);
            Assert.AreEqual("ES", response.Registrant.Address[3]);

            Assert.AreEqual("+34.932701520", response.Registrant.TelephoneNumber);
            Assert.AreEqual("Amadeu@abril.info", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("ento0027519", response.AdminContact.RegistryId);
            Assert.AreEqual("Amadeu Abril i Abril", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Carrer del Carme 47", response.AdminContact.Address[0]);
            Assert.AreEqual("Barcelona", response.AdminContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.AdminContact.Address[2]);
            Assert.AreEqual("08001", response.AdminContact.Address[3]);
            Assert.AreEqual("ES", response.AdminContact.Address[4]);

            Assert.AreEqual("+34.932701520", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dominisadmin@mac.com", response.AdminContact.Email);

             // BillingContact Details
            Assert.AreEqual("ento0027519", response.BillingContact.RegistryId);
            Assert.AreEqual("Amadeu Abril i Abril", response.BillingContact.Name);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Carrer del Carme 47", response.BillingContact.Address[0]);
            Assert.AreEqual("Barcelona", response.BillingContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.BillingContact.Address[2]);
            Assert.AreEqual("08001", response.BillingContact.Address[3]);
            Assert.AreEqual("ES", response.BillingContact.Address[4]);

            Assert.AreEqual("+34.932701520", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("dominisadmin@mac.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("ento0027519", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Amadeu Abril i Abril", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Carrer del Carme 47", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Barcelona", response.TechnicalContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("08001", response.TechnicalContact.Address[3]);
            Assert.AreEqual("ES", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+34.932701520", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dominisadmin@mac.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns14.zoneedit.com", response.NameServers[0]);
            Assert.AreEqual("ns12.zoneedit.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited, clientDeleteProhibited", response.DomainStatus[0]);

            Assert.AreEqual(48, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found_status_ok.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cat/cat/Found", response.TemplateName);

            Assert.AreEqual("gencat.cat", response.DomainName.ToString());
            Assert.AreEqual("REG-D3862", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2009, 3, 31, 16, 22, 42, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("NOM_P_15605701", response.Registrant.RegistryId);
            Assert.AreEqual("Generalitat de Catalunya Departament de la Presidencia", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Laietana, 14", response.Registrant.Address[0]);
            Assert.AreEqual("Barcelona", response.Registrant.Address[1]);
            Assert.AreEqual("BARCELONA", response.Registrant.Address[2]);
            Assert.AreEqual("08003", response.Registrant.Address[3]);
            Assert.AreEqual("ES", response.Registrant.Address[4]);

            Assert.AreEqual("+34.935676330", response.Registrant.TelephoneNumber);
            Assert.AreEqual("jcolomer@gencat.net", response.Registrant.Email);

             // AdminContact Details
            Assert.AreEqual("NOM_8727301", response.AdminContact.RegistryId);
            Assert.AreEqual("Marta Continente Gonzalo", response.AdminContact.Name);
            Assert.AreEqual("Generalitat de Catalunya Departament de la Presidencia (2)", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Via Laietana, 14", response.AdminContact.Address[0]);
            Assert.AreEqual("Barcelona", response.AdminContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.AdminContact.Address[2]);
            Assert.AreEqual("08003", response.AdminContact.Address[3]);
            Assert.AreEqual("ES", response.AdminContact.Address[4]);

            Assert.AreEqual("+34.935676330", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+34.935676331", response.AdminContact.FaxNumber);
            Assert.AreEqual("dominisgencat@gencat.net", response.AdminContact.Email);

             // BillingContact Details
            Assert.AreEqual("NOM_8727401", response.BillingContact.RegistryId);
            Assert.AreEqual("Jaume Colomer Garcia", response.BillingContact.Name);
            Assert.AreEqual("Generalitat de Catalunya - Departament de la Presidencia", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Via Laietana, 14", response.BillingContact.Address[0]);
            Assert.AreEqual("Barcelona", response.BillingContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.BillingContact.Address[2]);
            Assert.AreEqual("08003", response.BillingContact.Address[3]);
            Assert.AreEqual("ES", response.BillingContact.Address[4]);

            Assert.AreEqual("+34.935676330", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+34.935676331", response.BillingContact.FaxNumber);
            Assert.AreEqual("dominisgencat@gencat.net", response.BillingContact.Email);

             // TechnicalContact Details
            Assert.AreEqual("NOM_8727401", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Jaume Colomer Garcia", response.TechnicalContact.Name);
            Assert.AreEqual("Generalitat de Catalunya - Departament de la Presidencia", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via Laietana, 14", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Barcelona", response.TechnicalContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("08003", response.TechnicalContact.Address[3]);
            Assert.AreEqual("ES", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+34.935676330", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+34.935676331", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dominisgencat@gencat.net", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("dns.gencat.net", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(51, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "not_found_status_available.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cat/cat/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.cat", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found_status_registered.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cat/cat/Found", response.TemplateName);

            Assert.AreEqual("gencat.cat", response.DomainName.ToString());
            Assert.AreEqual("REG-D3862", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2013, 11, 27, 17, 30, 59, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("CD126562321349", response.Registrant.RegistryId);
            Assert.AreEqual("Departament de la Presidencia - Generalitat de Catalunya", response.Registrant.Name);
            Assert.AreEqual("Departament de la Presidencia - Generalitat de Catalunya", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Via Laietana, 14", response.Registrant.Address[0]);
            Assert.AreEqual("Barcelona", response.Registrant.Address[1]);
            Assert.AreEqual("Barcelona", response.Registrant.Address[2]);
            Assert.AreEqual("08003", response.Registrant.Address[3]);
            Assert.AreEqual("ES", response.Registrant.Address[4]);

            Assert.AreEqual("+34.935676330", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dominisgencat@gencat.cat", response.Registrant.Email);

             // AdminContact Details
            Assert.AreEqual("CD126562321411", response.AdminContact.RegistryId);
            Assert.AreEqual("Direccio General Atencio Ciutadana i Difusio (Generalitat de Catalunya)", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Via Laietana, 14", response.AdminContact.Address[0]);
            Assert.AreEqual("Barcelona", response.AdminContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.AdminContact.Address[2]);
            Assert.AreEqual("08003", response.AdminContact.Address[3]);
            Assert.AreEqual("ES", response.AdminContact.Address[4]);

            Assert.AreEqual("+34.935676330", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dominisgencat@gencat.cat", response.AdminContact.Email);

             // BillingContact Details
            Assert.AreEqual("CD126562321532", response.BillingContact.RegistryId);
            Assert.AreEqual("DGAC Direccio General Atencio Ciutadana", response.BillingContact.Name);
            Assert.AreEqual("DGAC Direccio General Atencio Ciutadana", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Via Laietana, 14", response.BillingContact.Address[0]);
            Assert.AreEqual("Barcelona", response.BillingContact.Address[1]);
            Assert.AreEqual("Barcelona", response.BillingContact.Address[2]);
            Assert.AreEqual("08003", response.BillingContact.Address[3]);
            Assert.AreEqual("ES", response.BillingContact.Address[4]);

            Assert.AreEqual("+34.935676330", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("dominisgencat@gencat.cat", response.BillingContact.Email);

             // TechnicalContact Details
            Assert.AreEqual("CD126562321482", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Carles Corcoll Lopez", response.TechnicalContact.Name);
            Assert.AreEqual("Carles Corcoll Lopez", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via Laietana 14 3a planta", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Barcelona", response.TechnicalContact.Address[1]);
            Assert.AreEqual("BARCELONA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("08003", response.TechnicalContact.Address[3]);
            Assert.AreEqual("ES", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+34.935676330", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dominisgencat@gencat.cat", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("dns.gencat.net", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(48, response.FieldsParsed);
        }
    }
}
