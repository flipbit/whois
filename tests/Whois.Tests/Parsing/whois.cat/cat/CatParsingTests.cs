using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cat.Cat
{
    public class CatParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CatParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "not_found.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);
            Assert.Equal(0, response.ParsingErrors);

            Assert.Equal("whois.cat/cat/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.cat", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cat/cat/Found", response.TemplateName);

            Assert.Equal("abril.cat", response.DomainName.ToString());
            Assert.Equal("REG-D42136", response.RegistryDomainId);

            Assert.Equal(new DateTime(2011, 1, 12, 16, 50, 9, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 4, 22, 09, 48, 30, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 4, 22, 09, 48, 30, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("edig-001455", response.Registrant.RegistryId);
            Assert.Equal("Amadeu Abril i Abril", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Carrer del carme 47", response.Registrant.Address[0]);
            Assert.Equal("Barcelona", response.Registrant.Address[1]);
            Assert.Equal("08001", response.Registrant.Address[2]);
            Assert.Equal("ES", response.Registrant.Address[3]);

            Assert.Equal("+34.932701520", response.Registrant.TelephoneNumber);
            Assert.Equal("Amadeu@abril.info", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("ento0027519", response.AdminContact.RegistryId);
            Assert.Equal("Amadeu Abril i Abril", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Carrer del Carme 47", response.AdminContact.Address[0]);
            Assert.Equal("Barcelona", response.AdminContact.Address[1]);
            Assert.Equal("BARCELONA", response.AdminContact.Address[2]);
            Assert.Equal("08001", response.AdminContact.Address[3]);
            Assert.Equal("ES", response.AdminContact.Address[4]);

            Assert.Equal("+34.932701520", response.AdminContact.TelephoneNumber);
            Assert.Equal("dominisadmin@mac.com", response.AdminContact.Email);

             // BillingContact Details
            Assert.Equal("ento0027519", response.BillingContact.RegistryId);
            Assert.Equal("Amadeu Abril i Abril", response.BillingContact.Name);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("Carrer del Carme 47", response.BillingContact.Address[0]);
            Assert.Equal("Barcelona", response.BillingContact.Address[1]);
            Assert.Equal("BARCELONA", response.BillingContact.Address[2]);
            Assert.Equal("08001", response.BillingContact.Address[3]);
            Assert.Equal("ES", response.BillingContact.Address[4]);

            Assert.Equal("+34.932701520", response.BillingContact.TelephoneNumber);
            Assert.Equal("dominisadmin@mac.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("ento0027519", response.TechnicalContact.RegistryId);
            Assert.Equal("Amadeu Abril i Abril", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Carrer del Carme 47", response.TechnicalContact.Address[0]);
            Assert.Equal("Barcelona", response.TechnicalContact.Address[1]);
            Assert.Equal("BARCELONA", response.TechnicalContact.Address[2]);
            Assert.Equal("08001", response.TechnicalContact.Address[3]);
            Assert.Equal("ES", response.TechnicalContact.Address[4]);

            Assert.Equal("+34.932701520", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("dominisadmin@mac.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns14.zoneedit.com", response.NameServers[0]);
            Assert.Equal("ns12.zoneedit.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited, clientDeleteProhibited", response.DomainStatus[0]);

            Assert.Equal(48, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found_status_ok.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cat/cat/Found", response.TemplateName);

            Assert.Equal("gencat.cat", response.DomainName.ToString());
            Assert.Equal("REG-D3862", response.RegistryDomainId);

            Assert.Equal(new DateTime(2009, 3, 31, 16, 22, 42, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("NOM_P_15605701", response.Registrant.RegistryId);
            Assert.Equal("Generalitat de Catalunya Departament de la Presidencia", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Via Laietana, 14", response.Registrant.Address[0]);
            Assert.Equal("Barcelona", response.Registrant.Address[1]);
            Assert.Equal("BARCELONA", response.Registrant.Address[2]);
            Assert.Equal("08003", response.Registrant.Address[3]);
            Assert.Equal("ES", response.Registrant.Address[4]);

            Assert.Equal("+34.935676330", response.Registrant.TelephoneNumber);
            Assert.Equal("jcolomer@gencat.net", response.Registrant.Email);

             // AdminContact Details
            Assert.Equal("NOM_8727301", response.AdminContact.RegistryId);
            Assert.Equal("Marta Continente Gonzalo", response.AdminContact.Name);
            Assert.Equal("Generalitat de Catalunya Departament de la Presidencia (2)", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Via Laietana, 14", response.AdminContact.Address[0]);
            Assert.Equal("Barcelona", response.AdminContact.Address[1]);
            Assert.Equal("BARCELONA", response.AdminContact.Address[2]);
            Assert.Equal("08003", response.AdminContact.Address[3]);
            Assert.Equal("ES", response.AdminContact.Address[4]);

            Assert.Equal("+34.935676330", response.AdminContact.TelephoneNumber);
            Assert.Equal("+34.935676331", response.AdminContact.FaxNumber);
            Assert.Equal("dominisgencat@gencat.net", response.AdminContact.Email);

             // BillingContact Details
            Assert.Equal("NOM_8727401", response.BillingContact.RegistryId);
            Assert.Equal("Jaume Colomer Garcia", response.BillingContact.Name);
            Assert.Equal("Generalitat de Catalunya - Departament de la Presidencia", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("Via Laietana, 14", response.BillingContact.Address[0]);
            Assert.Equal("Barcelona", response.BillingContact.Address[1]);
            Assert.Equal("BARCELONA", response.BillingContact.Address[2]);
            Assert.Equal("08003", response.BillingContact.Address[3]);
            Assert.Equal("ES", response.BillingContact.Address[4]);

            Assert.Equal("+34.935676330", response.BillingContact.TelephoneNumber);
            Assert.Equal("+34.935676331", response.BillingContact.FaxNumber);
            Assert.Equal("dominisgencat@gencat.net", response.BillingContact.Email);

             // TechnicalContact Details
            Assert.Equal("NOM_8727401", response.TechnicalContact.RegistryId);
            Assert.Equal("Jaume Colomer Garcia", response.TechnicalContact.Name);
            Assert.Equal("Generalitat de Catalunya - Departament de la Presidencia", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Via Laietana, 14", response.TechnicalContact.Address[0]);
            Assert.Equal("Barcelona", response.TechnicalContact.Address[1]);
            Assert.Equal("BARCELONA", response.TechnicalContact.Address[2]);
            Assert.Equal("08003", response.TechnicalContact.Address[3]);
            Assert.Equal("ES", response.TechnicalContact.Address[4]);

            Assert.Equal("+34.935676330", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+34.935676331", response.TechnicalContact.FaxNumber);
            Assert.Equal("dominisgencat@gencat.net", response.TechnicalContact.Email);

            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("dns.gencat.net", response.NameServers[0]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(51, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "not_found_status_available.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cat/cat/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.cat", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found_status_registered.txt");
            var response = parser.Parse("whois.cat", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cat/cat/Found", response.TemplateName);

            Assert.Equal("gencat.cat", response.DomainName.ToString());
            Assert.Equal("REG-D3862", response.RegistryDomainId);

            Assert.Equal(new DateTime(2013, 11, 27, 17, 30, 59, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2020, 2, 14, 9, 12, 37, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("CD126562321349", response.Registrant.RegistryId);
            Assert.Equal("Departament de la Presidencia - Generalitat de Catalunya", response.Registrant.Name);
            Assert.Equal("Departament de la Presidencia - Generalitat de Catalunya", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("Via Laietana, 14", response.Registrant.Address[0]);
            Assert.Equal("Barcelona", response.Registrant.Address[1]);
            Assert.Equal("Barcelona", response.Registrant.Address[2]);
            Assert.Equal("08003", response.Registrant.Address[3]);
            Assert.Equal("ES", response.Registrant.Address[4]);

            Assert.Equal("+34.935676330", response.Registrant.TelephoneNumber);
            Assert.Equal("dominisgencat@gencat.cat", response.Registrant.Email);

             // AdminContact Details
            Assert.Equal("CD126562321411", response.AdminContact.RegistryId);
            Assert.Equal("Direccio General Atencio Ciutadana i Difusio (Generalitat de Catalunya)", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Via Laietana, 14", response.AdminContact.Address[0]);
            Assert.Equal("Barcelona", response.AdminContact.Address[1]);
            Assert.Equal("BARCELONA", response.AdminContact.Address[2]);
            Assert.Equal("08003", response.AdminContact.Address[3]);
            Assert.Equal("ES", response.AdminContact.Address[4]);

            Assert.Equal("+34.935676330", response.AdminContact.TelephoneNumber);
            Assert.Equal("dominisgencat@gencat.cat", response.AdminContact.Email);

             // BillingContact Details
            Assert.Equal("CD126562321532", response.BillingContact.RegistryId);
            Assert.Equal("DGAC Direccio General Atencio Ciutadana", response.BillingContact.Name);
            Assert.Equal("DGAC Direccio General Atencio Ciutadana", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("Via Laietana, 14", response.BillingContact.Address[0]);
            Assert.Equal("Barcelona", response.BillingContact.Address[1]);
            Assert.Equal("Barcelona", response.BillingContact.Address[2]);
            Assert.Equal("08003", response.BillingContact.Address[3]);
            Assert.Equal("ES", response.BillingContact.Address[4]);

            Assert.Equal("+34.935676330", response.BillingContact.TelephoneNumber);
            Assert.Equal("dominisgencat@gencat.cat", response.BillingContact.Email);

             // TechnicalContact Details
            Assert.Equal("CD126562321482", response.TechnicalContact.RegistryId);
            Assert.Equal("Carles Corcoll Lopez", response.TechnicalContact.Name);
            Assert.Equal("Carles Corcoll Lopez", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Via Laietana 14 3a planta", response.TechnicalContact.Address[0]);
            Assert.Equal("Barcelona", response.TechnicalContact.Address[1]);
            Assert.Equal("BARCELONA", response.TechnicalContact.Address[2]);
            Assert.Equal("08003", response.TechnicalContact.Address[3]);
            Assert.Equal("ES", response.TechnicalContact.Address[4]);

            Assert.Equal("+34.935676330", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("dominisgencat@gencat.cat", response.TechnicalContact.Email);

            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("dns.gencat.net", response.NameServers[0]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(48, response.FieldsParsed);
        }
    }
}
